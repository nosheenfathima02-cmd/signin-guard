"""Detection rules for identity attacks, each mapped to MITRE ATT&CK."""
import math
from collections import defaultdict
from dataclasses import dataclass, asdict, field
from datetime import datetime

FAILED_PASSWORD = {50126, 50053, 50055}   # bad password, locked, expired
MFA_DENIED = {500121}


@dataclass
class Alert:
    rule: str
    severity: str
    mitre: str
    user: str
    ip: str
    first_seen: str
    last_seen: str
    summary: str
    evidence: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


def _ts(e):
    return datetime.strptime(e["createdDateTime"], "%Y-%m-%dT%H:%M:%SZ")


def _failed(e):
    return e.get("status", {}).get("errorCode") in FAILED_PASSWORD


def _ok(e):
    return e.get("status", {}).get("errorCode") == 0


def brute_force(logs, threshold=10, window_min=10):
    """Many failed passwords for one user from one IP in a short window (T1110.001).
    Escalates to high when a success from the same IP follows."""
    alerts = []
    by_key = defaultdict(list)
    for e in logs:
        by_key[(e["userPrincipalName"], e["ipAddress"])].append(e)
    for (user, ip), events in by_key.items():
        events.sort(key=_ts)
        fails = [e for e in events if _failed(e)]
        for i in range(len(fails)):
            j = i
            while j < len(fails) and (_ts(fails[j]) - _ts(fails[i])).total_seconds() <= window_min * 60:
                j += 1
            if j - i >= threshold:
                burst = fails[i:j]
                success = next((e for e in events if _ok(e) and _ts(e) > _ts(burst[-1])), None)
                alerts.append(Alert(
                    rule="Brute force" + (" followed by successful sign-in" if success else ""),
                    severity="high" if success else "medium",
                    mitre="T1110.001" + (", T1078" if success else ""),
                    user=user, ip=ip,
                    first_seen=burst[0]["createdDateTime"],
                    last_seen=(success or burst[-1])["createdDateTime"],
                    summary=f"{len(burst)} failed passwords in {window_min} min from {ip}"
                            + ("; then a successful sign-in. Treat account as compromised." if success else "."),
                    evidence=[e["id"] for e in burst + ([success] if success else [])]))
                break
    return alerts


def password_spray(logs, min_users=5, window_min=30):
    """One IP failing against many different users (T1110.003)."""
    alerts = []
    by_ip = defaultdict(list)
    for e in logs:
        if _failed(e):
            by_ip[e["ipAddress"]].append(e)
    for ip, fails in by_ip.items():
        fails.sort(key=_ts)
        for i in range(len(fails)):
            win = [e for e in fails[i:] if (_ts(e) - _ts(fails[i])).total_seconds() <= window_min * 60]
            users = {e["userPrincipalName"] for e in win}
            if len(users) >= min_users:
                alerts.append(Alert(
                    rule="Password spray", severity="high", mitre="T1110.003",
                    user=f"{len(users)} accounts", ip=ip,
                    first_seen=win[0]["createdDateTime"], last_seen=win[-1]["createdDateTime"],
                    summary=f"{ip} tried {len(users)} different accounts in {window_min} min.",
                    evidence=[e["id"] for e in win]))
                break
    return alerts


def _km(a, b):
    la1, lo1 = math.radians(a["latitude"]), math.radians(a["longitude"])
    la2, lo2 = math.radians(b["latitude"]), math.radians(b["longitude"])
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6371 * math.asin(math.sqrt(h))


def impossible_travel(logs, max_kmh=900):
    """Two successful sign-ins whose distance/time implies faster-than-airliner travel (T1078)."""
    alerts = []
    by_user = defaultdict(list)
    for e in logs:
        if _ok(e) and e.get("location", {}).get("geoCoordinates"):
            by_user[e["userPrincipalName"]].append(e)
    for user, events in by_user.items():
        events.sort(key=_ts)
        for a, b in zip(events, events[1:]):
            km = _km(a["location"]["geoCoordinates"], b["location"]["geoCoordinates"])
            hours = max((_ts(b) - _ts(a)).total_seconds() / 3600, 1 / 60)
            if km > 500 and km / hours > max_kmh:
                alerts.append(Alert(
                    rule="Impossible travel", severity="high", mitre="T1078",
                    user=user, ip=b["ipAddress"],
                    first_seen=a["createdDateTime"], last_seen=b["createdDateTime"],
                    summary=f"{a['location']['city']} to {b['location']['city']} ({km:,.0f} km) "
                            f"in {hours * 60:.0f} min, about {km / hours:,.0f} km/h.",
                    evidence=[a["id"], b["id"]]))
                break  # one alert per user; later legs of the same trip add noise, not signal
    return alerts


def mfa_fatigue(logs, threshold=5, window_min=15):
    """Repeated MFA push denials for one user, worst when an approval follows (T1621)."""
    alerts = []
    by_user = defaultdict(list)
    for e in logs:
        if "mfaDetail" in e:
            by_user[e["userPrincipalName"]].append(e)
    for user, events in by_user.items():
        events.sort(key=_ts)
        denied = [e for e in events if e["status"]["errorCode"] in MFA_DENIED]
        if len(denied) < threshold:
            continue
        span = (_ts(denied[-1]) - _ts(denied[0])).total_seconds() / 60
        if span > window_min:
            continue
        approved = next((e for e in events if e["mfaDetail"].get("result") == "approved"
                         and _ts(e) > _ts(denied[-1])), None)
        alerts.append(Alert(
            rule="MFA fatigue" + (" with approval" if approved else ""),
            severity="critical" if approved else "medium", mitre="T1621",
            user=user, ip=denied[0]["ipAddress"],
            first_seen=denied[0]["createdDateTime"],
            last_seen=(approved or denied[-1])["createdDateTime"],
            summary=f"{len(denied)} MFA pushes denied in {span:.0f} min"
                    + ("; user then approved one. Revoke sessions and reset credentials." if approved else "."),
            evidence=[e["id"] for e in denied + ([approved] if approved else [])]))
    return alerts


RULES = [brute_force, password_spray, impossible_travel, mfa_fatigue]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def run_all(logs):
    alerts = [a for rule in RULES for a in rule(logs)]
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER[a.severity], a.first_seen))
