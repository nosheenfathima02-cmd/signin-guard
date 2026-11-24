"""Generate synthetic Entra ID sign-in logs with known attacks mixed into normal traffic.

Field names follow the Microsoft Graph signIn resource so the detector also runs on
real exports (Entra admin center -> Sign-in logs -> Download -> JSON).
"""
import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

USERS = [f"{n}@contoso.ca" for n in
         ["aisha.khan", "ben.tremblay", "chen.li", "diana.roy", "omar.haddad",
          "priya.patel", "sam.nguyen", "tara.singh", "victor.costa", "zoe.martin"]]
TORONTO = {"city": "Toronto", "countryOrRegion": "CA", "geoCoordinates": {"latitude": 43.65, "longitude": -79.38}}
OTTAWA = {"city": "Ottawa", "countryOrRegion": "CA", "geoCoordinates": {"latitude": 45.42, "longitude": -75.69}}
LAGOS = {"city": "Lagos", "countryOrRegion": "NG", "geoCoordinates": {"latitude": 6.52, "longitude": 3.38}}
MOSCOW = {"city": "Moscow", "countryOrRegion": "RU", "geoCoordinates": {"latitude": 55.75, "longitude": 37.62}}
APPS = ["Office 365 Exchange Online", "Microsoft Teams", "SharePoint Online", "Azure Portal"]


def event(ts, user, ip, loc, error=0, mfa=None, app=None):
    e = {
        "id": str(uuid.uuid4()),
        "createdDateTime": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "userPrincipalName": user,
        "ipAddress": ip,
        "appDisplayName": app or random.choice(APPS),
        "location": loc,
        "status": {"errorCode": error},
    }
    if mfa:
        e["mfaDetail"] = {"authMethod": "Microsoft Authenticator push", "result": mfa}
    return e


def generate(seed=7):
    random.seed(seed)
    start = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)
    logs = []
    # Normal business traffic: each user signs in a few times a day from Toronto/Ottawa.
    for day in range(3):
        for user in USERS:
            for _ in range(random.randint(2, 4)):
                ts = start + timedelta(days=day, minutes=random.randint(0, 600))
                loc = TORONTO if random.random() < 0.85 else OTTAWA
                err = 50126 if random.random() < 0.05 else 0  # occasional typo
                logs.append(event(ts, user, f"142.114.{random.randint(1, 254)}.{random.randint(1, 254)}", loc, err))

    t = start + timedelta(days=1, hours=2)
    # 1. Brute force then success on one account (T1110.001 -> T1078)
    for i in range(14):
        logs.append(event(t + timedelta(seconds=20 * i), "chen.li@contoso.ca", "185.220.101.44", MOSCOW, 50126))
    logs.append(event(t + timedelta(seconds=300), "chen.li@contoso.ca", "185.220.101.44", MOSCOW, 0))

    # 2. Password spray: one IP, one attempt per user (T1110.003)
    t2 = start + timedelta(days=1, hours=5)
    for i, user in enumerate(USERS):
        logs.append(event(t2 + timedelta(seconds=40 * i), user, "45.153.160.2", LAGOS, 50126))

    # 3. Impossible travel: Toronto then Lagos 40 minutes later (T1078)
    t3 = start + timedelta(days=2, hours=1)
    logs.append(event(t3, "diana.roy@contoso.ca", "142.114.9.10", TORONTO, 0))
    logs.append(event(t3 + timedelta(minutes=40), "diana.roy@contoso.ca", "102.89.33.7", LAGOS, 0))

    # 4. MFA fatigue: repeated push denials then an approval (T1621)
    t4 = start + timedelta(days=2, hours=3)
    for i in range(7):
        logs.append(event(t4 + timedelta(minutes=i), "omar.haddad@contoso.ca", "91.243.44.12", MOSCOW, 500121, mfa="denied"))
    logs.append(event(t4 + timedelta(minutes=8), "omar.haddad@contoso.ca", "91.243.44.12", MOSCOW, 0, mfa="approved"))

    logs.sort(key=lambda e: e["createdDateTime"])
    return logs


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample_data/signins.json"
    with open(out, "w") as f:
        json.dump(generate(), f, indent=1)
    print(f"Wrote {out}")
