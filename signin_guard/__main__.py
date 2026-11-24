"""CLI: python -m signin_guard <signins.json> [--html report.html] [--wazuh alerts.jsonl]"""
import argparse
import json

from .detections import run_all
from .report import render


def main(argv=None):
    p = argparse.ArgumentParser(prog="signin_guard", description="Detect identity attacks in Entra ID sign-in logs.")
    p.add_argument("logs", help="Entra ID sign-in log export (JSON array, or {'value': [...]} from Graph)")
    p.add_argument("--html", help="write an HTML incident report")
    p.add_argument("--wazuh", help="write JSON lines for a SIEM (e.g. Wazuh) to ingest")
    args = p.parse_args(argv)

    with open(args.logs) as f:
        data = json.load(f)
    logs = data["value"] if isinstance(data, dict) else data
    alerts = run_all(logs)

    for a in alerts:
        print(f"[{a.severity.upper():8}] {a.rule:45} {a.user:28} {a.mitre}")
    print(f"\n{len(alerts)} alerts from {len(logs)} events")

    if args.html:
        with open(args.html, "w") as f:
            f.write(render(alerts, len(logs)))
        print(f"HTML report: {args.html}")
    if args.wazuh:
        with open(args.wazuh, "w") as f:
            for a in alerts:
                f.write(json.dumps({"signin_guard": a.to_dict()}) + "\n")
        print(f"SIEM feed: {args.wazuh}")
    return alerts


if __name__ == "__main__":
    main()
