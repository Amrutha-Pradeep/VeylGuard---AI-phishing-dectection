import pytest
from app.detector import analyze_rules, calculate_risk


# ── Helper ─────────────────────────────────────────────────────────────────

def _risk(sender="friend@example.com", subject="Hello", body="Hi there"):
    findings = analyze_rules(sender, subject, body)
    return findings, calculate_risk(findings)


# ── Existing tests ─────────────────────────────────────────────────────────

def test_suspicious_email_gets_findings():
    findings = analyze_rules(
        "security@example.com",
        "URGENT: verify now",
        "Your account will be suspended. Send your password at http://192.168.1.10/login",
    )
    assert findings
    risk = calculate_risk(findings)
    assert risk["score"] > 0
    assert risk["category"] in {"Low", "Medium", "High", "Critical"}


def test_plain_email_can_have_zero_rule_score():
    findings = analyze_rules(
        "friend@example.com",
        "Lunch tomorrow",
        "Hi, are we still meeting at noon tomorrow?",
    )
    risk = calculate_risk(findings)
    assert risk["score"] == 0
    assert risk["category"] == "Low"


# ── URL / link tests ───────────────────────────────────────────────────────

def test_http_url_flagged():
    findings, _ = _risk(body="Click here: http://example.com/login")
    ids = [f["id"] for f in findings]
    assert "suspicious_url" in ids


def test_ip_address_url_flagged():
    findings, _ = _risk(body="Visit http://192.168.0.1/login to verify")
    ids = [f["id"] for f in findings]
    assert "suspicious_url" in ids


def test_url_shortener_flagged():
    findings, _ = _risk(body="See this: https://bit.ly/abc123")
    ids = [f["id"] for f in findings]
    assert "suspicious_url" in ids


def test_https_normal_domain_not_flagged_for_url():
    findings, _ = _risk(body="Check https://www.legitimate-company.com/info")
    ids = [f["id"] for f in findings]
    assert "suspicious_url" not in ids


# ── Urgency tests ──────────────────────────────────────────────────────────

def test_urgency_phrase_flagged():
    findings, _ = _risk(subject="URGENT", body="You must act now or your account will be suspended.")
    ids = [f["id"] for f in findings]
    assert "urgency" in ids


def test_final_warning_flagged():
    findings, _ = _risk(body="This is your final warning. Respond immediately.")
    ids = [f["id"] for f in findings]
    assert "urgency" in ids


# ── Sensitive information tests ────────────────────────────────────────────

def test_password_request_flagged():
    findings, _ = _risk(body="Please enter your password and credit card below.")
    ids = [f["id"] for f in findings]
    assert "sensitive_request" in ids


def test_otp_request_flagged():
    findings, _ = _risk(body="Enter your OTP to continue.")
    ids = [f["id"] for f in findings]
    assert "sensitive_request" in ids


# ── Sender domain tests ────────────────────────────────────────────────────

def test_suspicious_sender_domain_flagged():
    findings, _ = _risk(sender="no-reply@secure-update-account.com")
    ids = [f["id"] for f in findings]
    assert "sender_domain" in ids


def test_clean_sender_domain_not_flagged():
    findings, _ = _risk(sender="hello@mycompany.com")
    ids = [f["id"] for f in findings]
    assert "sender_domain" not in ids


# ── Display name / domain mismatch tests ──────────────────────────────────

def test_paypal_display_name_mismatch_flagged():
    # Domain must NOT contain "paypal" — otherwise it's considered a legitimate match
    findings, _ = _risk(sender='PayPal <support@secure-verification-center.com>')
    ids = [f["id"] for f in findings]
    assert "display_name_mismatch" in ids


def test_amazon_display_name_mismatch_flagged():
    findings, _ = _risk(sender='Amazon <noreply@amazon-security-alert.com>')
    ids = [f["id"] for f in findings]
    # The domain contains "amazon" so it should NOT fire (it's a match)
    # Re-test with a clearly different domain
    findings2, _ = _risk(sender='Amazon <noreply@phishing-shop.co>')
    ids2 = [f["id"] for f in findings2]
    assert "display_name_mismatch" in ids2


def test_legitimate_paypal_sender_not_flagged():
    # Domain contains "paypal" so display name matches
    findings, _ = _risk(sender='PayPal <service@paypal.com>')
    ids = [f["id"] for f in findings]
    assert "display_name_mismatch" not in ids


# ── Generic greeting tests ─────────────────────────────────────────────────

def test_dear_customer_greeting_flagged():
    findings, _ = _risk(body="Dear Customer, your account requires attention.")
    ids = [f["id"] for f in findings]
    assert "generic_greeting" in ids


def test_dear_valued_customer_flagged():
    findings, _ = _risk(body="Dear Valued Customer, please verify your details.")
    ids = [f["id"] for f in findings]
    assert "generic_greeting" in ids


def test_personalized_greeting_not_flagged():
    findings, _ = _risk(body="Hi John, hope you are well.")
    ids = [f["id"] for f in findings]
    assert "generic_greeting" not in ids


# ── Attachment lure tests ──────────────────────────────────────────────────

def test_attached_invoice_flagged():
    findings, _ = _risk(body="Please find attached invoice for your records.")
    ids = [f["id"] for f in findings]
    assert "attachment_lure" in ids


def test_open_attached_document_flagged():
    findings, _ = _risk(body="Open the attached document to view your statement.")
    ids = [f["id"] for f in findings]
    assert "attachment_lure" in ids


def test_no_attachment_mention_not_flagged():
    findings, _ = _risk(body="See you at the meeting tomorrow, no files needed.")
    ids = [f["id"] for f in findings]
    assert "attachment_lure" not in ids


def test_ambiguous_attachment_reference_has_low_advisory_score():
    findings, risk = _risk(
        body="Please review the attached invoice when convenient."
    )
    assert [finding["id"] for finding in findings] == ["attachment_lure"]
    assert risk["score"] == 15
    assert risk["category"] == "Low"


# ── Risk score / category boundary tests ──────────────────────────────────

def test_score_capped_at_100():
    # Pile on all indicators to test cap
    findings = analyze_rules(
        'PayPal <evil@phishing-site.ru>',
        "URGENT: act now — final warning",
        (
            "Dear Customer, your account will be suspended within 24 hours. "
            "Send your password, credit card, and OTP to http://192.168.1.1/steal. "
            "Please find attached invoice."
        ),
    )
    risk = calculate_risk(findings)
    assert risk["score"] <= 100


def test_critical_threshold():
    # Force a score >= 75
    group_points = {"url": 25, "sensitive": 25, "sender": 25, "urgency": 10}
    findings = [
        {"group": g, "points": p, "id": g, "title": g, "severity": "high", "evidence": g}
        for g, p in group_points.items()
    ]
    risk = calculate_risk(findings)
    assert risk["score"] == 85
    assert risk["category"] == "Critical"


def test_high_threshold():
    findings = [
        {"group": "url", "points": 20, "id": "u", "title": "u", "severity": "high", "evidence": "u"},
        {"group": "sensitive", "points": 20, "id": "s", "title": "s", "severity": "high", "evidence": "s"},
        {"group": "social", "points": 10, "id": "g", "title": "g", "severity": "low", "evidence": "g"},
    ]
    risk = calculate_risk(findings)
    assert risk["score"] == 50
    assert risk["category"] == "High"


def test_medium_threshold():
    findings = [
        {"group": "urgency", "points": 10, "id": "u", "title": "u", "severity": "medium", "evidence": "u"},
        {"group": "social", "points": 5, "id": "g", "title": "g", "severity": "low", "evidence": "g"},
        {"group": "sender", "points": 10, "id": "s", "title": "s", "severity": "low", "evidence": "s"},
    ]
    risk = calculate_risk(findings)
    assert risk["score"] == 25
    assert risk["category"] == "Medium"


def test_calculate_risk_returns_all_fields():
    findings, risk = _risk()
    assert "score" in risk
    assert "category" in risk
    assert "breakdown" in risk
    assert "evidence" in risk
