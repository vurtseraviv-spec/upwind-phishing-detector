import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("phishing_detector")

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")


def _get_api_key() -> str:
    key = os.getenv("GEMINI_API_KEY", "").strip()
    if key.upper() in ("", "NONE", "DISABLED", "NULL"):
        return ""
    return key


def get_ai_engine_status() -> str:
    return f"Gemini Live ({GEMINI_MODEL})" if _get_api_key() else "Autonomous SOC Engine (Built-in)"


def _call_gemini(prompt: str, expect_json: bool = False) -> Tuple[Optional[str], Optional[str]]:
    api_key = _get_api_key()
    if not api_key:
        return None, None

    candidate_models: List[str] = [GEMINI_MODEL]
    for alt in ("gemini-flash-lite-latest", "gemini-flash-latest", "gemini-2.5-flash-lite"):
        if alt not in candidate_models:
            candidate_models.append(alt)

    payload: Dict[str, Any] = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.25,
            "maxOutputTokens": 700,
        },
    }
    if expect_json:
        payload["generationConfig"]["responseMimeType"] = "application/json"

    body_bytes = json.dumps(payload).encode("utf-8")

    for model in candidate_models:
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={api_key}"
        )
        attempts = 2 if model == GEMINI_MODEL else 1
        for attempt in range(attempts):
            req = urllib.request.Request(
                url,
                data=body_bytes,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(req, timeout=25) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates") or []
                if not candidates:
                    break
                parts = candidates[0].get("content", {}).get("parts", [])
                text = "".join(p.get("text", "") for p in parts).strip()
                if text:
                    return text, model
                break
            except urllib.error.HTTPError as exc:
                err_body = ""
                try:
                    err_body = exc.read().decode("utf-8", errors="ignore")[:300]
                except Exception:
                    pass
                logger.warning("Gemini API HTTP %s (%s): %s", exc.code, model, err_body)
                if exc.code in (429, 500, 502, 503, 504) and attempt + 1 < attempts:
                    time.sleep(1.2)
                    continue
                if exc.code in (401, 403):
                    return None, None
                break
            except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError) as exc:
                logger.warning("Gemini API call failed (%s): %s", model, exc)
                break

    return None, None


def _strip_json_fences(raw: str) -> str:
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _heuristic_investigation(scan: Dict[str, Any]) -> Dict[str, Any]:
    score = scan.get("risk_score", 0)
    indicators = scan.get("indicators", [])
    iocs_raw = scan.get("iocs") or {}
    categories = {i.get("category") for i in indicators}

    mitre: List[Dict[str, str]] = []
    if "Attachment Analysis" in categories:
        mitre.append({
            "id": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "reason": "Malicious or deceptive file attachment detected in email payload.",
        })
    if "Suspicious Link" in categories:
        mitre.append({
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "reason": "Direct IP, shortened, or lookalike brand URL identified in message body.",
        })
    if "Spoofed Sender" in categories:
        mitre.append({
            "id": "T1656",
            "name": "Impersonation",
            "reason": "Sender domain spoofing, Reply-To mismatch, or SPF/DKIM authentication failure.",
        })
    if "Suspicious Wording" in categories:
        mitre.append({
            "id": "T1204",
            "name": "User Execution / Social Engineering",
            "reason": "Urgency, account suspension threats, or financial lures designed to bypass user scrutiny.",
        })
    if not mitre and score < 20:
        mitre.append({
            "id": "NONE",
            "name": "No Adversarial Technique Observed",
            "reason": "Message headers, links, and wording align with benign communication.",
        })

    if "Attachment Analysis" in categories and "Suspicious Link" in categories:
        attack_type = "Hybrid Credential Harvesting & Malware Dropper"
    elif "Attachment Analysis" in categories:
        attack_type = "Malware / Payload Delivery via Attachment"
    elif "Suspicious Link" in categories:
        attack_type = "Credential Harvesting (Phishing Link)"
    elif any("financial" in i.get("detail", "").lower() or "bec" in i.get("detail", "").lower() for i in indicators):
        attack_type = "Business Email Compromise (BEC) / Wire Fraud"
    elif score >= 20:
        attack_type = "Social Engineering / Suspicious Outreach"
    else:
        attack_type = "Legitimate Communication"

    ioc_list: List[Dict[str, str]] = []
    for ip in iocs_raw.get("ips", []):
        ioc_list.append({"type": "IP", "value": ip, "risk": "CRITICAL"})
    for dom in iocs_raw.get("domains", []):
        ioc_list.append({"type": "DOMAIN", "value": dom, "risk": "HIGH"})
    for url in iocs_raw.get("urls", []):
        ioc_list.append({"type": "URL", "value": url, "risk": "HIGH"})
    for att in iocs_raw.get("attachments", []):
        ioc_list.append({"type": "ATTACHMENT", "value": att, "risk": "CRITICAL"})

    sender = scan.get("sender", "Unknown")
    subject = scan.get("subject", "(No Subject)")

    if score >= 45:
        summary = (
            f"Automated triage classified '{subject}' from {sender} as {attack_type} "
            f"(Risk {score}/100 across {len(indicators)} indicators). "
            f"High-confidence deception signals require immediate quarantine and IOC blocking."
        )
        remediation = [
            f"Quarantine all matching messages across mailboxes (Subject: '{subject}').",
            "Block extracted sender domains, malicious IPs, and redirect URLs at the Secure Email Gateway & DNS firewall.",
            "Audit IAM / SSO sign-in logs for any recipient who may have interacted with the link or attachment.",
            "Enforce strict DMARC (p=reject) and alert targeted users with an internal phishing advisory.",
        ]
        confidence = "HIGH"
    elif score >= 20:
        summary = (
            f"Message '{subject}' from {sender} triggered {len(indicators)} moderate anomaly signals "
            f"(Risk {score}/100). Recommended for manual SOC analyst verification before user interaction."
        )
        remediation = [
            "Hold email in sandbox/quarantine pending out-of-band verification with the purported sender.",
            "Inspect embedded links in an isolated browser sandbox before permitting delivery.",
            "Monitor related domains for follow-up campaign activity across the organization.",
        ]
        confidence = "MEDIUM"
    else:
        summary = (
            f"Automated triage found no phishing artifacts in '{subject}' from {sender} (Risk {score}/100). "
            f"Authentication signals and content profile appear consistent with legitimate traffic."
        )
        remediation = [
            "No containment action required; allow normal delivery.",
            "Retain telemetry record in audit log for baseline correlation.",
        ]
        confidence = "HIGH"

    timeline = [
        {"step": "1. Header & Auth Inspection", "status": "DONE", "detail": f"Evaluated sender '{sender}' and Reply-To/SPF/DKIM signals."},
        {"step": "2. IOC & Payload Extraction", "status": "DONE", "detail": f"Extracted {len(ioc_list)} actionable IOC(s) and {len(scan.get('attachments', []))} attachment(s)."},
        {"step": "3. MITRE ATT&CK Correlation", "status": "DONE", "detail": f"Mapped detection to {len(mitre)} technique(s) and generated SOC playbook."},
    ]

    return {
        "engine": "Autonomous SOC Engine (Built-in)",
        "attack_type": attack_type,
        "confidence": confidence,
        "executive_summary": summary,
        "mitre_attack": mitre,
        "iocs": ioc_list,
        "remediation_steps": remediation,
        "timeline": timeline,
    }


def investigate_scan(scan: Dict[str, Any]) -> Dict[str, Any]:
    fallback = _heuristic_investigation(scan)
    if not _get_api_key():
        return fallback

    prompt = f"""You are a Senior Cloud Security & SOC Analyst at Upwind Security.
Investigate this scanned email and return ONLY valid JSON matching this exact schema:
{{
  "attack_type": "short string classification",
  "confidence": "HIGH | MEDIUM | LOW",
  "executive_summary": "2-3 concise sentences explaining the attacker's goal and risk",
  "mitre_attack": [{{"id": "T1566.xxx", "name": "Technique Name", "reason": "short specific reason"}}],
  "remediation_steps": ["concrete SOC action 1", "concrete SOC action 2", "concrete SOC action 3", "concrete SOC action 4"]
}}

Email telemetry:
- Sender: {scan.get("sender")}
- Reply-To: {scan.get("reply_to")}
- Subject: {scan.get("subject")}
- Risk Score: {scan.get("risk_score")}/100 ({scan.get("risk_level")})
- Indicators: {json.dumps(scan.get("indicators", [])[:12])}
- IOCs: {json.dumps(scan.get("iocs", {}))}
- Attachments: {json.dumps(scan.get("attachments", []))}
- Body Excerpt: {scan.get("body_excerpt", "")[:500]}
"""
    raw, used_model = _call_gemini(prompt, expect_json=True)
    if not raw:
        return fallback

    try:
        parsed = json.loads(_strip_json_fences(raw))
        return {
            "engine": f"Gemini Live ({used_model or GEMINI_MODEL})",
            "attack_type": str(parsed.get("attack_type") or fallback["attack_type"]),
            "confidence": str(parsed.get("confidence") or fallback["confidence"]),
            "executive_summary": str(parsed.get("executive_summary") or fallback["executive_summary"]),
            "mitre_attack": parsed.get("mitre_attack") or fallback["mitre_attack"],
            "iocs": fallback["iocs"],
            "remediation_steps": parsed.get("remediation_steps") or fallback["remediation_steps"],
            "timeline": fallback["timeline"],
        }
    except Exception as exc:
        logger.warning("Failed to parse Gemini investigation JSON: %s", exc)
        return fallback


def _heuristic_chat(message: str, active_scan: Optional[Dict[str, Any]], metrics: Dict[str, Any]) -> str:
    q = message.strip().lower()

    if re.fullmatch(r"(hi|hello|hey|yo|sup|good morning|good evening|help)[!?. ]*", q):
        ctx = (
            f"I currently have Scan #{active_scan.get('id')} ({active_scan.get('risk_score')}/100) loaded in context."
            if active_scan else
            "No scan is selected yet — run an email scan or click View in the history table."
        )
        return (
            f"Hi! I am your SOC AI Security Analyst. {ctx}\n"
            "You can ask me to explain the threat, extract IOCs, map MITRE ATT&CK techniques, "
            "draft an employee security advisory, or summarize live platform metrics."
        )

    if any(k in q for k in ("warn", "employee", "staff", "draft", "advisory", "alert email", "notify")):
        subj = active_scan.get("subject", "Suspicious Account Notice") if active_scan else "Recent Phishing Campaign"
        sender = active_scan.get("sender", "external spoofed sender") if active_scan else "unknown external sender"
        return (
            f"Subject: [SECURITY ADVISORY] Active Phishing Attempt Detected\n\n"
            f"Team,\n"
            f"Our monitoring system intercepted a phishing email impersonating a trusted service:\n"
            f"- Apparent Sender: {sender}\n"
            f"- Subject Line: {subj}\n\n"
            f"Action Required:\n"
            f"1. Do NOT click any links or download attachments from this message.\n"
            f"2. Report and delete the email immediately.\n"
            f"3. If you already entered credentials, reset your password and notify Security immediately."
        )

    if any(k in q for k in ("summary", "metrics", "stats", "trend", "recent", "overall", "how many")):
        return (
            f"Live SOC Telemetry Summary:\n"
            f"- Total Scans Processed: {metrics.get('total_scans', 0)}\n"
            f"- Phishing Detected: {metrics.get('phishing_count', 0)} ({metrics.get('detection_rate_pct', 0)}% threat rate)\n"
            f"- Average Risk Score: {metrics.get('avg_risk_score', 0)}/100\n"
            f"- Redis Cache Hit Rate: {metrics.get('cache_hit_rate_pct', 0)}%\n"
            f"- Average Processing Latency: {metrics.get('avg_latency_ms', 0)} ms\n"
            f"Top detected categories: "
            + (", ".join(f"{k} ({v})" for k, v in (metrics.get("category_distribution") or {}).items() if v > 0) or "None yet")
            + "."
        )

    if active_scan:
        score = active_scan.get("risk_score", 0)
        verdict = active_scan.get("verdict", "Unknown")
        inds = active_scan.get("indicators", [])
        iocs = active_scan.get("iocs", {})

        if any(k in q for k in ("block", "remediat", "mitigat", "fix", "contain", "soc", "action", "do next")):
            domains = ", ".join(iocs.get("domains", [])) or "sender domain"
            ips = ", ".join(iocs.get("ips", [])) or "N/A"
            return (
                f"Recommended Containment Plan for Scan #{active_scan.get('id', '?')} ({verdict}):\n"
                f"1. Block suspicious domain(s) [{domains}] and IP(s) [{ips}] at the email gateway & firewall.\n"
                f"2. Purge matching messages with subject '{active_scan.get('subject')}' from user inboxes.\n"
                f"3. Check CloudWatch/SSO logs for outbound clicks or credential reuse.\n"
                f"4. Verify SPF/DKIM/DMARC enforcement is set to reject spoofed traffic."
            )

        if any(k in q for k in ("mitre", "tactic", "technique", "kill chain", "attack")):
            inv = _heuristic_investigation(active_scan)
            tactics = "\n".join(f"- {m['id']} ({m['name']}): {m['reason']}" for m in inv["mitre_attack"])
            return f"MITRE ATT&CK Mapping for '{active_scan.get('subject')}':\n{tactics}"

        top_reasons = "\n".join(
            f"- [{i['severity']} +{i['points']}] {i['category']}: {i['detail']}"
            for i in inds[:5]
        ) or "- No malicious indicators were triggered."
        return (
            f"Analysis of Scan #{active_scan.get('id', '?')} — {verdict} ({score}/100):\n"
            f"Sender: {active_scan.get('sender')}\n"
            f"Key Findings:\n{top_reasons}\n\n"
            f"Ask me to 'draft an employee warning', 'map to MITRE ATT&CK', or 'generate containment steps'."
        )

    return (
        "I am your AI Security Analyst. Scan or select an email from the History table, then ask me:\n"
        "- Why was this email flagged?\n"
        "- Draft an employee warning advisory\n"
        "- What MITRE ATT&CK techniques apply?\n"
        "- Summarize recent threat metrics"
    )


def chat_with_analyst(
    message: str,
    active_scan: Optional[Dict[str, Any]],
    metrics: Dict[str, Any],
) -> Dict[str, Any]:
    suggested = [
        "Explain why this email is dangerous",
        "Draft an employee warning email",
        "What MITRE ATT&CK tactics are used?",
        "Summarize overall threat metrics",
    ]

    if _get_api_key():
        context_blob = {
            "active_scan": {
                "id": active_scan.get("id"),
                "sender": active_scan.get("sender"),
                "subject": active_scan.get("subject"),
                "risk_score": active_scan.get("risk_score"),
                "verdict": active_scan.get("verdict"),
                "indicators": (active_scan.get("indicators") or [])[:10],
                "iocs": active_scan.get("iocs") or {},
                "attachments": active_scan.get("attachments") or [],
            } if active_scan else None,
            "platform_metrics": {
                "total_scans": metrics.get("total_scans"),
                "phishing_count": metrics.get("phishing_count"),
                "detection_rate_pct": metrics.get("detection_rate_pct"),
                "cache_hit_rate_pct": metrics.get("cache_hit_rate_pct"),
                "category_distribution": metrics.get("category_distribution"),
            },
        }
        prompt = (
            "You are an expert SOC & Cloud Security AI Analyst embedded inside an Email Phishing Detector dashboard. "
            "Answer the analyst's question naturally, concisely, and concretely using the telemetry context below. "
            "Respond in the same language the user asked in (default English).\n\n"
            f"Telemetry Context:\n{json.dumps(context_blob, indent=2)}\n\n"
            f"User Question: {message}"
        )
        live_reply, used_model = _call_gemini(prompt, expect_json=False)
        if live_reply:
            return {
                "reply": live_reply,
                "engine": f"Gemini Live ({used_model or GEMINI_MODEL})",
                "suggested_followups": suggested,
            }

    return {
        "reply": _heuristic_chat(message, active_scan, metrics),
        "engine": "Autonomous SOC Engine (Built-in)",
        "suggested_followups": suggested,
    }
