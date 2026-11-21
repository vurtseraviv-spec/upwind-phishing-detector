import argparse
import json
import sys
from pathlib import Path

from app.ai_engine import investigate_scan
from app.detector import analyze_email


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan an email file (.txt or .eml) for phishing indicators.")
    parser.add_argument("file", type=Path, help="Path to the text/eml file containing email content")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted summary")
    parser.add_argument("--investigate", action="store_true", help="Also run autonomous AI threat investigation")
    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File '{args.file}' not found.", file=sys.stderr)
        sys.exit(1)

    raw_content = args.file.read_text(encoding="utf-8", errors="replace")
    result = analyze_email(raw_content, filename=args.file.name)
    if args.investigate:
        result["investigation"] = investigate_scan(result)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("=" * 64)
    print(f"File:       {result['filename']}")
    print(f"Sender:     {result['sender']}")
    print(f"Subject:    {result['subject']}")
    print(f"Verdict:    {result['verdict']} ({result['risk_level']})")
    print(f"Risk Score: {result['risk_score']}/100")
    print("=" * 64)

    if result["indicators"]:
        print(f"\nDetected Indicators ({result['indicator_count']}):")
        for idx, ind in enumerate(result["indicators"], start=1):
            print(f"  {idx}. [{ind['severity']} | +{ind['points']} pts] ({ind['category']}) {ind['detail']}")
    else:
        print("\nNo phishing indicators detected.")

    if result["attachments"]:
        print("\nAttachments:")
        for att in result["attachments"]:
            print(f"  - {att['filename']} | risk={att.get('risk')} | sha256={att.get('sha256') or 'N/A'}")

    if args.investigate and result.get("investigation"):
        inv = result["investigation"]
        print("\n--- AI Threat Investigation ---")
        print(f"Engine:     {inv['engine']}")
        print(f"Attack:     {inv['attack_type']} (Confidence: {inv['confidence']})")
        print(f"Summary:    {inv['executive_summary']}")
        print("MITRE ATT&CK:")
        for m in inv["mitre_attack"]:
            print(f"  - {m['id']} ({m['name']}): {m['reason']}")


if __name__ == "__main__":
    main()
