"""Render alerts as a self-contained HTML incident dashboard."""
import html
from collections import Counter

COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b8860b", "low": "#2f6f4f"}
PLAYBOOK = {
    "Brute force": "Confirm with the user, block the IP at Conditional Access, check for a later successful sign-in.",
    "Password spray": "Block the source IP, review every targeted account for a success, enforce MFA and smart lockout.",
    "Impossible travel": "Check for VPN use, revoke refresh tokens, require password reset if the user did not travel.",
    "MFA fatigue": "Revoke all sessions, reset password, switch the user to number-matching MFA, contact the user.",
}


def _playbook(rule):
    return next(v for k, v in PLAYBOOK.items() if rule.startswith(k))


def render(alerts, total_events):
    sev = Counter(a.severity for a in alerts)
    tiles = "".join(
        f'<div class="tile"><b style="color:{COLORS[s]}">{sev.get(s, 0)}</b><span>{s}</span></div>'
        for s in ["critical", "high", "medium"])
    rows = "".join(f"""
      <tr>
        <td><span class="pill" style="background:{COLORS[a.severity]}">{a.severity}</span></td>
        <td><b>{html.escape(a.rule)}</b><div class="muted">{html.escape(a.summary)}</div>
            <div class="play">Response: {html.escape(_playbook(a.rule))}</div></td>
        <td>{html.escape(a.user)}</td><td><code>{html.escape(a.ip)}</code></td>
        <td><code>{a.mitre}</code></td>
        <td class="muted">{a.first_seen}<br>{a.last_seen}</td>
      </tr>""" for a in alerts)
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SignIn Guard Report</title>
<style>
 body{{font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;background:#f6f7f9;color:#1b2430}}
 h1{{margin:0 0 4px}} .muted{{color:#5b6675;font-size:12.5px}}
 .tiles{{display:flex;gap:12px;margin:16px 0;flex-wrap:wrap}}
 .tile{{background:#fff;border:1px solid #dde2e8;border-radius:8px;padding:12px 18px;min-width:110px}}
 .tile b{{font-size:28px;display:block}} .tile span{{text-transform:uppercase;font-size:11px;letter-spacing:.06em}}
 .wrap{{overflow-x:auto;background:#fff;border:1px solid #dde2e8;border-radius:8px}}
 table{{border-collapse:collapse;width:100%;min-width:760px}} td,th{{padding:10px 12px;border-bottom:1px solid #eef1f4;vertical-align:top;text-align:left}}
 th{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#5b6675}}
 .pill{{color:#fff;border-radius:99px;padding:2px 10px;font-size:12px}} .play{{font-size:12.5px;margin-top:4px}}
</style></head><body>
<h1>SignIn Guard: identity threat report</h1>
<div class="muted">{total_events} sign-in events analysed · {len(alerts)} alerts · MITRE ATT&amp;CK mapped</div>
<div class="tiles">{tiles}</div>
<div class="wrap"><table><tr><th>Severity</th><th>Detection</th><th>User</th><th>Source IP</th><th>ATT&amp;CK</th><th>First / last seen (UTC)</th></tr>{rows}</table></div>
</body></html>"""
