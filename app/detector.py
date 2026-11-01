import re
from urllib.parse import urlparse


URL_PATTERN = re.compile(r"https?://[^\s<>\]\[\"']+", re.IGNORECASE)

URGENCY_PHRASES = (
    "urgent", "immediately", "act now", "account will be suspended",
    "verify now", "within 24 hours", "final warning", "unusual activity",
    "last chance", "account suspended", "limited time", "action required",
    "respond immediately", "your account has been", "access will be terminated",
    "failure to respond", "24-hour notice", "48-hour notice",
)

SENSITIVE_PHRASES = (
    "password", "one-time password", "otp", "bank details",
    "credit card", "debit card", "social security", "payment details",
    "login credentials", "confirm your account", "ssn", "routing number",
    "account number", "pin number", "cvv", "card number", "wire transfer",
    "bank account", "mother's maiden name", "date of birth",
)

GENERIC_GREETINGS = (
    "dear customer", "dear user", "dear account holder",
    "dear valued customer", "dear member", "dear client",
    "hello user", "hi user", "dear sir", "dear madam",
)

ATTACHMENT_LURE_PHRASES = (
    "attached invoice", "open the attached", "see attached",
    "attached document", "attachment contains", "attached file",
    "please find attached", "download the attached", "open the document",
    "invoice attached", "receipt attached", "statement attached",
)

# Well-known brands that phishers commonly spoof in display names
SPOOFED_BRAND_NAMES = (
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "bank of america", "chase", "wells fargo", "citibank",
    "dropbox", "linkedin", "twitter", "instagram", "whatsapp", "ebay",
    "irs", "fedex", "ups", "dhl", "usps",
)


def _extract_display_name_and_domain(sender: str):
    """
    Parse a sender field that may look like:
        PayPal <support@some-bad-domain.com>
        support@example.com
    Returns (display_name_lower, email_domain_lower).
    """
    match = re.match(r"^(.+?)\s*<([^>]+)>$", sender.strip())
    if match:
        display_name = match.group(1).strip().strip('"').lower()
        email_part = match.group(2).strip().lower()
    else:
        display_name = ""
        email_part = sender.strip().lower()

    domain = email_part.rsplit("@", 1)[-1] if "@" in email_part else ""
    return display_name, domain


def analyze_rules(sender, subject, body):
    """Find phishing indicators using transparent, predefined rules."""
    text = f"{sender}\n{subject}\n{body}".lower()
    findings = []

    # ── Rule 1: Suspicious URLs ───────────────────────────────────────────────
    urls = URL_PATTERN.findall(f"{subject}\n{body}")
    suspicious_urls = []
    for raw_url in urls:
        cleaned = raw_url.rstrip(".,);")
        parsed = urlparse(cleaned)
        host = (parsed.hostname or "").lower()
        reasons = []
        if parsed.scheme == "http":
            reasons.append("uses unencrypted HTTP")
        if host and re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            reasons.append("uses an IP address instead of a domain name")
        if any(shortener in host for shortener in (
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
            "ow.ly", "goo.gl", "short.ly", "snip.ly",
        )):
            reasons.append("uses a URL-shortening service")
        if reasons:
            suspicious_urls.append({"url": cleaned, "reasons": reasons})

    if suspicious_urls:
        evidence = "; ".join(
            f"{item['url']} ({', '.join(item['reasons'])})"
            for item in suspicious_urls[:5]
        )
        findings.append({
            "id": "suspicious_url",
            "title": "Suspicious link",
            "group": "url",
            "severity": "high",
            "points": 20,
            "evidence": evidence,
        })

    # ── Rule 2: Urgent / threatening language ─────────────────────────────────
    urgency_matches = [phrase for phrase in URGENCY_PHRASES if phrase in text]
    if urgency_matches:
        findings.append({
            "id": "urgency",
            "title": "Urgent or threatening language",
            "group": "urgency",
            "severity": "medium",
            "points": 10,
            "evidence": ", ".join(urgency_matches[:6]),
        })

    # ── Rule 3: Sensitive information requested ───────────────────────────────
    sensitive_matches = [phrase for phrase in SENSITIVE_PHRASES if phrase in text]
    if sensitive_matches:
        findings.append({
            "id": "sensitive_request",
            "title": "Sensitive information requested",
            "group": "sensitive",
            "severity": "high",
            "points": 20,
            "evidence": ", ".join(sensitive_matches[:6]),
        })

    # ── Rule 4: Suspicious sender domain tokens ───────────────────────────────
    _, sender_domain = _extract_display_name_and_domain(sender)
    if sender_domain and any(
        token in sender_domain
        for token in ("secure-", "verify-", "account-", "update-", "login-",
                      "confirm-", "alert-", "support-", "service-")
    ):
        findings.append({
            "id": "sender_domain",
            "title": "Sender domain deserves review",
            "group": "sender",
            "severity": "low",
            "points": 10,
            "evidence": f"Sender domain: {sender_domain}",
        })

    # ── Rule 5: Display name / domain brand mismatch ─────────────────────────
    display_name, email_domain = _extract_display_name_and_domain(sender)
    if display_name and email_domain:
        for brand in SPOOFED_BRAND_NAMES:
            if brand in display_name and brand not in email_domain:
                # The display name claims to be the brand but the domain is different
                findings.append({
                    "id": "display_name_mismatch",
                    "title": "Display name does not match sender domain",
                    "group": "sender",
                    "severity": "high",
                    "points": 25,
                    "evidence": (
                        f"Display name mentions '{brand.title()}' "
                        f"but the actual sending domain is '{email_domain}'"
                    ),
                })
                break  # One finding per sender is enough

    # ── Rule 6: Generic / impersonal greeting ────────────────────────────────
    body_lower = body.lower()
    greeting_matches = [g for g in GENERIC_GREETINGS if g in body_lower]
    if greeting_matches:
        findings.append({
            "id": "generic_greeting",
            "title": "Generic, impersonal greeting",
            "group": "social",
            "severity": "low",
            "points": 5,
            "evidence": ", ".join(greeting_matches[:3]),
        })

    # ── Rule 7: Attachment lure ───────────────────────────────────────────────
    attachment_matches = [p for p in ATTACHMENT_LURE_PHRASES if p in body_lower]
    if attachment_matches:
        findings.append({
            "id": "attachment_lure",
            "title": "Attachment-based lure detected",
            "group": "attachment",
            "severity": "medium",
            "points": 15,
            "evidence": ", ".join(attachment_matches[:4]),
        })

    return findings


def calculate_risk(findings):
    """Calculate a capped score from the strongest finding in each group."""
    group_points = {}
    for finding in findings:
        group = finding.get("group", "other")
        group_points[group] = max(
            group_points.get(group, 0),
            int(finding.get("points", 0)),
        )

    score = min(100, sum(group_points.values()))
    if score >= 75:
        category = "Critical"
    elif score >= 50:
        category = "High"
    elif score >= 25:
        category = "Medium"
    else:
        category = "Low"

    breakdown = [
        {"group": group, "points": points}
        for group, points in group_points.items()
    ]
    evidence = [finding["evidence"] for finding in findings]
    return {
        "score": score,
        "category": category,
        "breakdown": breakdown,
        "evidence": evidence,
    }
