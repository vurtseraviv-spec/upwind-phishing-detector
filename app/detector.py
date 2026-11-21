import email
import hashlib
import re
from email import policy
from email.utils import parseaddr
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

PROTECTED_DOMAINS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "netflix.com", "facebook.com", "linkedin.com", "instagram.com",
    "upwind.io", "chase.com", "bankofamerica.com", "wellsfargo.com",
    "leumi.co.il", "bankhapoalim.co.il", "dropbox.com", "docusign.com",
    "github.com", "okta.com", "aws.amazon.com",
]

SUSPICIOUS_TLDS = {
    "xyz", "top", "ru", "tk", "ml", "ga", "cf", "gq", "zip", "mov",
    "click", "loan", "work", "buzz", "country", "stream", "info", "cn"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rb.gy",
    "is.gd", "buff.ly", "cutt.ly", "shorturl.at"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".jse",
    ".vbs", ".vbe", ".ps1", ".hta", ".msi", ".iso", ".img", ".lnk", ".jar"
}

MACRO_OR_ARCHIVE_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".gz", ".cab", ".html", ".htm"
}

SUSPICIOUS_PHRASES: List[Tuple[str, str, int]] = [
    (r"\b(urgent|immediately|action required|act now|final notice|last warning|asap)\b", "Urgency / pressure language", 12),
    (r"\b(verify your account|confirm your identity|update your payment|billing information|validate credentials)\b", "Credential / payment harvesting request", 18),
    (r"\b(account (has been )?(suspended|locked|compromised|disabled|limited))\b", "Account suspension threat", 18),
    (r"\b(within 24 hours|within 48 hours|expires? today|will be terminated|end of business)\b", "Artificial deadline threat", 12),
    (r"\b(click (here|below|the link)|log ?in (here|now|immediately))\b", "Call-to-action link lure", 10),
    (r"\b(wire transfer|gift card|bitcoin|crypto wallet|unusual sign-?in|reset your password|bank details|routing number)\b", "Financial or security lure", 15),
    (r"\b(congratulations|you have won|claim your prize|inheritance|lottery)\b", "Reward / prize scam wording", 15),
    (r"\b(keep this confidential|do not discuss|between us|i am in a meeting)\b", "BEC secrecy / social engineering cue", 16),
    (r"\bdear (customer|user|valued member|account holder)\b", "Generic impersonal greeting", 6),
]

HOMOGLYPH_MAP = str.maketrans({
    "0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "@": "a"
})


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(domain: str) -> str:
    d = domain.lower().translate(HOMOGLYPH_MAP)
    return d.replace("rn", "m").replace("vv", "w")


def _extract_domain(addr: str) -> str:
    _, email_addr = parseaddr(addr or "")
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].strip().lower()
    match = re.search(r"[\w.+-]+@([\w.-]+\.[a-zA-Z]{2,})", addr or "")
    return match.group(1).lower() if match else ""


def _parse_email_input(raw_content: str) -> Dict[str, Any]:
    msg = email.message_from_string(raw_content, policy=policy.default)
    headers = {
        "from": str(msg.get("From", "") or ""),
        "reply_to": str(msg.get("Reply-To", "") or ""),
        "return_path": str(msg.get("Return-Path", "") or ""),
        "subject": str(msg.get("Subject", "") or ""),
        "auth_results": str(msg.get("Authentication-Results", "") or ""),
    }

    plain_parts: List[str] = []
    html_parts: List[str] = []
    attachments: List[Dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            disposition = str(part.get_content_disposition() or "")
            filename = part.get_filename()
            if filename or disposition == "attachment":
                payload = part.get_payload(decode=True) or b""
                attachments.append({
                    "filename": filename or "unnamed_attachment",
                    "content_type": part.get_content_type(),
                    "size_bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest() if payload else None,
                    "source": "mime_attachment",
                })
                continue

            ctype = part.get_content_type()
            try:
                text = part.get_content()
            except Exception:
                payload = part.get_payload(decode=True) or b""
                text = payload.decode("utf-8", errors="ignore")

            if isinstance(text, str):
                if ctype == "text/html":
                    html_parts.append(text)
                elif ctype == "text/plain":
                    plain_parts.append(text)
    else:
        try:
            body = msg.get_content()
        except Exception:
            body = raw_content
        if isinstance(body, str):
            if msg.get_content_type() == "text/html":
                html_parts.append(body)
            else:
                plain_parts.append(body)

    if not headers["from"]:
        m = re.search(r"(?im)^from:\s*(.+)$", raw_content)
        if m:
            headers["from"] = m.group(1).strip()
    if not headers["subject"]:
        m = re.search(r"(?im)^subject:\s*(.+)$", raw_content)
        if m:
            headers["subject"] = m.group(1).strip()
    if not headers["reply_to"]:
        m = re.search(r"(?im)^reply-to:\s*(.+)$", raw_content)
        if m:
            headers["reply_to"] = m.group(1).strip()

    body_text = "\n".join(plain_parts).strip() or raw_content
    html_text = "\n".join(html_parts).strip()

    for m in re.finditer(r"(?im)^(?:attachment|file|attached)\s*:\s*([^\r\n]+)$", raw_content):
        fname = m.group(1).strip()
        if fname and not any(a["filename"] == fname for a in attachments):
            attachments.append({
                "filename": fname,
                "content_type": "text/declared",
                "size_bytes": None,
                "sha256": None,
                "source": "text_header",
            })

    return {
        "headers": headers,
        "body_text": body_text,
        "html_text": html_text,
        "attachments": attachments,
    }


def _check_sender(headers: Dict[str, str], indicators: List[Dict[str, Any]], iocs: Dict[str, set]) -> int:
    score = 0
    from_raw = headers["from"]
    from_domain = _extract_domain(from_raw)
    reply_domain = _extract_domain(headers["reply_to"])
    return_domain = _extract_domain(headers["return_path"])
    display_name, _ = parseaddr(from_raw)

    if from_domain:
        norm_from = _normalize_homoglyphs(from_domain)
        for legit in PROTECTED_DOMAINS:
            if from_domain == legit:
                break
            legit_base = legit.split(".")[0]
            if _levenshtein(from_domain, legit) <= 2 or _levenshtein(norm_from, legit) <= 2:
                indicators.append({
                    "category": "Spoofed Sender",
                    "severity": "HIGH",
                    "points": 30,
                    "detail": f"Sender domain '{from_domain}' closely mimics legitimate domain '{legit}'.",
                })
                iocs["domains"].add(from_domain)
                score += 30
                break
            if legit_base in norm_from and not from_domain.endswith("." + legit):
                indicators.append({
                    "category": "Spoofed Sender",
                    "severity": "HIGH",
                    "points": 25,
                    "detail": f"Sender domain '{from_domain}' contains brand name '{legit_base}' but is not '{legit}'.",
                })
                iocs["domains"].add(from_domain)
                score += 25
                break

        if display_name:
            disp_lower = display_name.lower()
            for legit in PROTECTED_DOMAINS:
                brand = legit.split(".")[0]
                if brand in disp_lower and not (from_domain == legit or from_domain.endswith("." + legit)):
                    indicators.append({
                        "category": "Spoofed Sender",
                        "severity": "HIGH",
                        "points": 22,
                        "detail": f"Display name '{display_name}' impersonates '{brand}', but email originates from '{from_domain}'.",
                    })
                    iocs["domains"].add(from_domain)
                    score += 22
                    break

        tld = from_domain.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            indicators.append({
                "category": "Spoofed Sender",
                "severity": "MEDIUM",
                "points": 12,
                "detail": f"Sender uses uncommon/high-risk TLD '.{tld}' ({from_domain}).",
            })
            iocs["domains"].add(from_domain)
            score += 12

    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append({
            "category": "Spoofed Sender",
            "severity": "MEDIUM",
            "points": 18,
            "detail": f"From domain ('{from_domain}') does not match Reply-To domain ('{reply_domain}').",
        })
        iocs["domains"].add(reply_domain)
        score += 18

    if from_domain and return_domain and from_domain != return_domain:
        indicators.append({
            "category": "Spoofed Sender",
            "severity": "LOW",
            "points": 8,
            "detail": f"From domain ('{from_domain}') differs from Return-Path ('{return_domain}').",
        })
        iocs["domains"].add(return_domain)
        score += 8

    auth = headers["auth_results"].lower()
    if any(fail in auth for fail in ("spf=fail", "dkim=fail", "dmarc=fail", "spf=softfail")):
        indicators.append({
            "category": "Spoofed Sender",
            "severity": "HIGH",
            "points": 25,
            "detail": f"Email authentication check failed in headers: {headers['auth_results'][:140]}",
        })
        score += 25

    return score


def _check_links(body_text: str, html_text: str, indicators: List[Dict[str, Any]], iocs: Dict[str, set]) -> int:
    score = 0
    combined = f"{body_text}\n{html_text}"
    urls = set(re.findall(r"https?://[^\s<>\"'\)\]]+", combined, flags=re.IGNORECASE))
    ip_regex = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

    for url in sorted(urls):
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host:
            continue

        flagged = False
        if ip_regex.match(host):
            indicators.append({
                "category": "Suspicious Link",
                "severity": "HIGH",
                "points": 25,
                "detail": f"Link points directly to an IP address instead of a domain: {url}",
            })
            iocs["ips"].add(host)
            iocs["urls"].add(url)
            score += 25
            continue

        if "@" in parsed.netloc:
            indicators.append({
                "category": "Suspicious Link",
                "severity": "HIGH",
                "points": 22,
                "detail": f"URL contains '@' symbol used to obscure true destination: {url}",
            })
            score += 22
            flagged = True

        if "xn--" in host:
            indicators.append({
                "category": "Suspicious Link",
                "severity": "HIGH",
                "points": 20,
                "detail": f"URL uses Punycode (potential IDN homograph attack): {url}",
            })
            score += 20
            flagged = True

        if host in URL_SHORTENERS:
            indicators.append({
                "category": "Suspicious Link",
                "severity": "MEDIUM",
                "points": 15,
                "detail": f"URL uses a link shortener that hides the true destination: {url}",
            })
            score += 15
            flagged = True

        tld = host.rsplit(".", 1)[-1] if "." in host else ""
        if tld in SUSPICIOUS_TLDS:
            indicators.append({
                "category": "Suspicious Link",
                "severity": "MEDIUM",
                "points": 15,
                "detail": f"URL uses high-risk/uncommon TLD '.{tld}': {url}",
            })
            score += 15
            flagged = True

        if host.count(".") >= 4:
            indicators.append({
                "category": "Suspicious Link",
                "severity": "MEDIUM",
                "points": 12,
                "detail": f"URL has excessive subdomains ({host}): {url}",
            })
            score += 12
            flagged = True

        if parsed.scheme == "http" and any(k in url.lower() for k in ("login", "verify", "account", "secure", "bank", "signin")):
            indicators.append({
                "category": "Suspicious Link",
                "severity": "MEDIUM",
                "points": 12,
                "detail": f"Sensitive login/verification link uses unencrypted HTTP: {url}",
            })
            score += 12
            flagged = True

        norm_host = _normalize_homoglyphs(host)
        for legit in PROTECTED_DOMAINS:
            brand = legit.split(".")[0]
            if brand in norm_host and not (host == legit or host.endswith("." + legit)):
                indicators.append({
                    "category": "Suspicious Link",
                    "severity": "HIGH",
                    "points": 22,
                    "detail": f"URL domain '{host}' mimics brand '{brand}' without belonging to '{legit}'.",
                })
                score += 22
                flagged = True
                break

        if flagged:
            iocs["urls"].add(url)
            iocs["domains"].add(host)

    if html_text:
        for href, label in re.findall(r'<a[^>]+href=["\'](https?://[^"\']+)["\'][^>]*>(.*?)</a>', html_text, flags=re.I | re.S):
            clean_label = re.sub(r"<[^>]+>", "", label).strip()
            if clean_label.startswith(("http://", "https://")):
                href_host = (urlparse(href).hostname or "").lower()
                label_host = (urlparse(clean_label).hostname or "").lower()
                if href_host and label_host and href_host != label_host:
                    indicators.append({
                        "category": "Suspicious Link",
                        "severity": "HIGH",
                        "points": 28,
                        "detail": f"Deceptive HTML link: text shows '{label_host}' but href points to '{href_host}'.",
                    })
                    iocs["urls"].add(href)
                    iocs["domains"].add(href_host)
                    score += 28

    return score


def _check_wording(subject: str, body_text: str, indicators: List[Dict[str, Any]]) -> int:
    score = 0
    full_text = f"{subject}\n{body_text}"
    for pattern, reason, points in SUSPICIOUS_PHRASES:
        match = re.search(pattern, full_text, flags=re.IGNORECASE)
        if match:
            indicators.append({
                "category": "Suspicious Wording",
                "severity": "MEDIUM" if points >= 15 else "LOW",
                "points": points,
                "detail": f"{reason} (matched: '{match.group(0)}').",
            })
            score += points

    if subject and subject.isupper() and len(subject) > 10:
        indicators.append({
            "category": "Suspicious Wording",
            "severity": "LOW",
            "points": 8,
            "detail": f"Subject line is in ALL CAPS: '{subject}'.",
        })
        score += 8

    return score


def _check_attachments(attachments: List[Dict[str, Any]], indicators: List[Dict[str, Any]], iocs: Dict[str, set]) -> int:
    score = 0
    for att in attachments:
        fname = att["filename"].lower().strip()
        parts = fname.split(".")
        ext = f".{parts[-1]}" if len(parts) > 1 else ""

        if len(parts) >= 3 and f".{parts[-1]}" in (DANGEROUS_EXTENSIONS | MACRO_OR_ARCHIVE_EXTENSIONS):
            indicators.append({
                "category": "Attachment Analysis",
                "severity": "CRITICAL",
                "points": 35,
                "detail": f"Suspicious double-extension attachment detected: '{att['filename']}'.",
            })
            iocs["attachments"].add(att["filename"])
            score += 35
            att["risk"] = "CRITICAL"
        elif ext in DANGEROUS_EXTENSIONS:
            indicators.append({
                "category": "Attachment Analysis",
                "severity": "CRITICAL",
                "points": 30,
                "detail": f"High-risk executable/script attachment detected: '{att['filename']}'.",
            })
            iocs["attachments"].add(att["filename"])
            score += 30
            att["risk"] = "HIGH"
        elif ext in MACRO_OR_ARCHIVE_EXTENSIONS:
            indicators.append({
                "category": "Attachment Analysis",
                "severity": "MEDIUM",
                "points": 15,
                "detail": f"Potentially risky macro/archive attachment: '{att['filename']}'.",
            })
            iocs["attachments"].add(att["filename"])
            score += 15
            att["risk"] = "MEDIUM"
        else:
            att["risk"] = "LOW"

    return score


def analyze_email(raw_content: str, filename: str = "pasted_email.txt") -> Dict[str, Any]:
    parsed = _parse_email_input(raw_content)
    indicators: List[Dict[str, Any]] = []
    iocs: Dict[str, set] = {"domains": set(), "urls": set(), "ips": set(), "attachments": set()}

    raw_score = 0
    raw_score += _check_sender(parsed["headers"], indicators, iocs)
    raw_score += _check_links(parsed["body_text"], parsed["html_text"], indicators, iocs)
    raw_score += _check_wording(parsed["headers"]["subject"], parsed["body_text"], indicators)
    raw_score += _check_attachments(parsed["attachments"], indicators, iocs)

    risk_score = min(100, raw_score)

    if risk_score >= 70:
        risk_level = "CRITICAL"
        is_phishing = True
        verdict = "Highly Likely Phishing Attempt"
    elif risk_score >= 45:
        risk_level = "HIGH"
        is_phishing = True
        verdict = "Likely Phishing Attempt"
    elif risk_score >= 20:
        risk_level = "MEDIUM"
        is_phishing = False
        verdict = "Suspicious - Review Carefully"
    else:
        risk_level = "LOW"
        is_phishing = False
        verdict = "Likely Legitimate"

    content_hash = hashlib.sha256(raw_content.encode("utf-8", errors="ignore")).hexdigest()

    return {
        "filename": filename,
        "content_hash": content_hash,
        "sender": parsed["headers"]["from"] or "Unknown",
        "reply_to": parsed["headers"]["reply_to"] or "",
        "subject": parsed["headers"]["subject"] or "(No Subject)",
        "body_excerpt": parsed["body_text"][:900],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "is_phishing": is_phishing,
        "verdict": verdict,
        "indicator_count": len(indicators),
        "indicators": indicators,
        "attachments": parsed["attachments"],
        "iocs": {k: sorted(v) for k, v in iocs.items()},
    }
