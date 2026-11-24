# SignIn Guard

Detects identity attacks in Microsoft Entra ID (Azure AD) sign-in logs, maps each alert to MITRE ATT&CK,
and sends alerts to a Wazuh SIEM or an HTML incident report. The same logic is included as Microsoft Sentinel KQL.

![HTML incident report generated from the sample data](docs/report.png)

| Detection | ATT&CK | Logic |
|---|---|---|
| Brute force (+ success) | T1110.001, T1078 | ≥10 failed passwords for one user from one IP in 10 min; high if a success follows |
| Password spray | T1110.003 | One IP failing against ≥5 accounts in 30 min |
| Impossible travel | T1078 | Two successful sign-ins >500 km apart faster than 900 km/h |
| MFA fatigue (+ approval) | T1621 | ≥5 denied MFA pushes in 15 min; critical if the user then approves |

Each alert in the report includes a response playbook step (revoke sessions, block the IP in Conditional Access, reset credentials).

## Run it

Needs Python 3.9+ and no other packages.

```bash
python -m signin_guard.generate_sample                 # synthetic logs with 4 planted attacks
python -m signin_guard sample_data/signins.json --html sample_data/report.html --wazuh sample_data/alerts.jsonl
python -m unittest                                     # 5 tests, including a false-positive check
```

Real data: Entra admin center → Monitoring → Sign-in logs → Download → JSON, then pass that file instead.

## Wazuh integration

1. Copy `wazuh/local_rules.xml` into `/var/ossec/etc/rules/local_rules.xml`.
2. In the agent's `ossec.conf` add:
   ```xml
   <localfile><log_format>json</log_format><location>/path/to/alerts.jsonl</location></localfile>
   ```
3. Restart the manager. Alerts appear under rule IDs 100501–100504 with MITRE tags.

## Microsoft Sentinel

`sentinel/hunting_queries.kql` has the brute-force, password-spray and MFA-fatigue detections as KQL against `SigninLogs`.

## Layout

```
signin_guard/detections.py      detection rules
signin_guard/report.py          HTML incident report
signin_guard/generate_sample.py synthetic Entra ID sign-in logs
wazuh/local_rules.xml           Wazuh custom rules
sentinel/hunting_queries.kql    Sentinel KQL equivalents
tests/                          unit tests
```
