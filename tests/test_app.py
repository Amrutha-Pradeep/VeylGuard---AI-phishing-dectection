"""
Integration tests for VeylGuard Flask routes.

External dependencies (Ollama HTTP calls) are mocked with
unittest.mock.patch so tests run without a running Ollama service.
"""

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

# ── Shared mock payloads ───────────────────────────────────────────────────

PHISHING_EMAIL = {
    "sender":  "PayPal <support@secure-verify-center.com>",
    "subject": "URGENT: Your account will be suspended",
    "body": (
        "Dear Customer, your account will be suspended within 24 hours. "
        "Send your password and OTP to http://192.168.1.1/steal. "
        "Please find attached invoice."
    ),
}

LEGITIMATE_EMAIL = {
    "sender":  "alice@example.com",
    "subject": "Lunch tomorrow?",
    "body":    "Hi, are we still on for lunch at noon?",
}

# A valid structured JSON response from the Ollama model
OLLAMA_PHISHING_RESPONSE = {
    "message": {
        "content": json.dumps({
            "verdict": "Likely Phishing",
            "confidence": 90,
            "reasons": ["Urgent language", "Suspicious IP link"],
            "evidence": ["Your account will be suspended", "http://192.168.1.1/steal"],
            "recommendations": ["Do not click links", "Contact bank directly"],
            "uncertainty": "Local model may make mistakes.",
        })
    }
}

OLLAMA_LEGITIMATE_RESPONSE = {
    "message": {
        "content": json.dumps({
            "verdict": "Likely Legitimate",
            "confidence": 80,
            "reasons": ["Casual language", "No suspicious links"],
            "evidence": ["Lunch tomorrow?"],
            "recommendations": ["No action required"],
            "uncertainty": "Local model may make mistakes.",
        })
    }
}

OLLAMA_TAGS_RESPONSE = {
    "models": [{"name": "qwen2.5:3b"}]
}


# ── Helper ─────────────────────────────────────────────────────────────────

def _mock_ollama_post(response_dict, status_code=200):
    """Return a mock that simulates a successful Ollama POST."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = response_dict
    mock.raise_for_status.return_value = None
    return mock


def _mock_ollama_get(response_dict, status_code=200):
    """Return a mock that simulates a successful Ollama GET."""
    mock = MagicMock()
    mock.status_code = status_code
    mock.json.return_value = response_dict
    mock.raise_for_status.return_value = None
    return mock


# ── Health endpoint ────────────────────────────────────────────────────────

class TestHealth:
    def test_ollama_online(self, client):
        with patch("app.requests.get",
                   return_value=_mock_ollama_get(OLLAMA_TAGS_RESPONSE)):
            res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "online"
        assert "qwen2.5:3b" in data["models"]
        assert data["active_model"] == "qwen2.5:3b"
        assert data["model_available"] is True

    def test_selected_model_missing(self, client):
        with patch("app.requests.get",
                   return_value=_mock_ollama_get({"models": []})):
            res = client.get("/api/health")
        assert res.status_code == 200
        data = res.get_json()
        assert data["status"] == "online"
        assert data["model_available"] is False

    def test_invalid_ollama_model_list_is_reported_offline(self, client):
        with patch("app.requests.get",
                   return_value=_mock_ollama_get({"models": "invalid"})):
            response = client.get("/api/health")
        assert response.status_code == 503
        assert response.get_json()["status"] == "offline"

    def test_ollama_offline(self, client):
        import requests as req
        with patch("app.requests.get",
                   side_effect=req.ConnectionError("refused")):
            res = client.get("/api/health")
        assert res.status_code == 503
        data = res.get_json()
        assert data["status"] == "offline"
        assert data["models"] == []


# ── Analyze endpoint — happy paths ─────────────────────────────────────────

class TestAnalyzeHappyPath:
    def test_phishing_email_returns_high_score(self, client, clean_db):
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_PHISHING_RESPONSE)):
            res = client.post(
                "/api/analyze",
                json=PHISHING_EMAIL,
                content_type="application/json",
            )
        assert res.status_code == 200
        data = res.get_json()

        # Combined score must be > 0
        assert data["score"] > 0
        assert data["category"] in {"Medium", "High", "Critical"}

        # Score breakdown fields present
        assert "rule_score" in data
        assert "rule_contribution" in data
        assert "ai_contribution" in data

        # Rule contribution is capped at 60
        assert data["rule_contribution"] <= 60

        # AI added some points (verdict=Likely Phishing, confidence=90)
        assert data["ai_contribution"] > 0

        # Combined score = rule_contribution + ai_contribution (capped at 100)
        expected = min(100, data["rule_contribution"] + data["ai_contribution"])
        assert data["score"] == expected

        # Findings are present
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) > 0

    def test_legitimate_email_returns_low_score(self, client, clean_db):
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_LEGITIMATE_RESPONSE)):
            res = client.post(
                "/api/analyze",
                json=LEGITIMATE_EMAIL,
                content_type="application/json",
            )
        assert res.status_code == 200
        data = res.get_json()
        assert data["score"] == 0
        assert data["category"] == "Low"
        # Legitimate verdict → 0 AI contribution
        assert data["ai_contribution"] == 0

    def test_response_contains_scoring_method(self, client, clean_db):
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_PHISHING_RESPONSE)):
            res = client.post("/api/analyze", json=PHISHING_EMAIL)
        data = res.get_json()
        assert "scoring_method" in data
        assert "60" in data["scoring_method"]   # 60 pt rule cap mentioned
        assert "40" in data["scoring_method"]   # 40 pt AI cap mentioned
        assert data["ai_analysis"]["evidence"]


# ── Analyze endpoint — Ollama unavailable ──────────────────────────────────

class TestAnalyzeOllamaUnavailable:
    def test_rules_still_run_when_ollama_is_down(self, client, clean_db):
        import requests as req
        with patch("app.requests.post",
                   side_effect=req.ConnectionError("Ollama not running")):
            res = client.post("/api/analyze", json=PHISHING_EMAIL)
        assert res.status_code == 200
        data = res.get_json()
        # Rules ran → score > 0
        assert data["rule_score"] > 0
        # AI unavailable → no AI contribution
        assert data["ai_contribution"] == 0
        # Error field explains the situation
        assert data["ai_error"] is not None

    def test_timeout_returns_rule_only_result(self, client, clean_db):
        import requests as req
        with patch("app.requests.post",
                   side_effect=req.Timeout("timed out")):
            res = client.post("/api/analyze", json=PHISHING_EMAIL)
        assert res.status_code == 200
        data = res.get_json()
        assert data["ai_error"] is not None
        assert data["ai_contribution"] == 0


# ── Analyze endpoint — invalid AI output ──────────────────────────────────

class TestAnalyzeInvalidAIOutput:
    def test_non_json_model_response_handled_gracefully(self, client, clean_db):
        bad_response = {"message": {"content": "not json at all!!!"}}
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(bad_response)):
            res = client.post("/api/analyze", json=PHISHING_EMAIL)
        assert res.status_code == 200
        data = res.get_json()
        assert data["ai_analysis"] is None
        assert data["ai_error"] is not None
        # Rules still scored
        assert data["rule_score"] > 0

    def test_invalid_verdict_handled_gracefully(self, client, clean_db):
        bad_verdict = {"message": {"content": json.dumps({
            "verdict": "UNKNOWN_VERDICT",
            "confidence": 50,
            "reasons": [],
            "evidence": [],
            "recommendations": [],
            "uncertainty": "",
        })}}
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(bad_verdict)):
            res = client.post("/api/analyze", json=PHISHING_EMAIL)
        assert res.status_code == 200
        data = res.get_json()
        assert data["ai_analysis"] is None
        assert data["ai_error"] is not None

    def test_missing_evidence_array_rejects_ai_output(self, client, clean_db):
        response_body = {"message": {"content": json.dumps({
            "verdict": "Suspicious",
            "confidence": 50,
            "reasons": ["Possible urgency"],
            "recommendations": ["Verify independently"],
            "uncertainty": "The result is uncertain.",
        })}}
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(response_body)):
            response = client.post("/api/analyze", json=PHISHING_EMAIL)
        assert response.status_code == 200
        assert response.get_json()["ai_analysis"] is None

    def test_invented_evidence_rejects_ai_output(self, client, clean_db):
        invented = json.loads(json.dumps(OLLAMA_PHISHING_RESPONSE))
        content = json.loads(invented["message"]["content"])
        content["evidence"] = ["The user must transfer money"]
        invented["message"]["content"] = json.dumps(content)
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(invented)):
            response = client.post("/api/analyze", json=PHISHING_EMAIL)
        assert response.status_code == 200
        assert response.get_json()["ai_analysis"] is None


# ── Analyze endpoint — input validation ───────────────────────────────────

class TestAnalyzeInputValidation:
    def test_malformed_json_returns_400(self, client):
        response = client.post(
            "/api/analyze",
            data="{broken json",
            content_type="application/json",
        )
        assert response.status_code == 400
        assert "error" in response.get_json()

    def test_missing_body_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={"sender": "a@b.com", "subject": "Hi"},
        )
        assert res.status_code == 400
        assert "error" in res.get_json()

    def test_empty_body_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={"sender": "a@b.com", "subject": "Hi", "body": "   "},
        )
        assert res.status_code == 400

    def test_missing_sender_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={"subject": "Hi", "body": "Some body text."},
        )
        assert res.status_code == 400

    def test_wrong_content_type_returns_415(self, client):
        res = client.post(
            "/api/analyze",
            data="sender=a@b.com&subject=Hi&body=text",
            content_type="application/x-www-form-urlencoded",
        )
        assert res.status_code == 415

    def test_oversized_body_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={
                "sender":  "a@b.com",
                "subject": "Hi",
                "body":    "x" * 20_001,
            },
        )
        assert res.status_code == 400
        assert "20,000" in res.get_json()["error"]

    def test_oversized_sender_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={
                "sender":  "a" * 255 + "@b.com",
                "subject": "Hi",
                "body":    "Some body.",
            },
        )
        assert res.status_code == 400

    def test_oversized_subject_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={
                "sender":  "a@b.com",
                "subject": "S" * 301,
                "body":    "Some body.",
            },
        )
        assert res.status_code == 400

    def test_non_string_field_returns_400(self, client):
        res = client.post(
            "/api/analyze",
            json={"sender": "a@b.com", "subject": ["bad"], "body": "Hello"},
        )
        assert res.status_code == 400

    def test_whitespace_is_trimmed_before_saving(self, client, clean_db):
        with patch("app.requests.post", side_effect=requests.ConnectionError):
            response = client.post("/api/analyze", json={
                "sender": "  person@example.com  ",
                "subject": "  Hello  ",
                "body": "  A short message.  ",
            })
        assert response.status_code == 200
        scan = client.get("/api/history").get_json()["history"][0]
        assert scan["sender"] == "person@example.com"
        assert scan["subject"] == "Hello"

    def test_email_body_is_not_saved_in_history(self, client, clean_db):
        secret_body = "Synthetic private text that must not be persisted."
        with patch("app.requests.post", side_effect=requests.ConnectionError):
            response = client.post("/api/analyze", json={
                "sender": "person@example.com",
                "subject": "Synthetic subject",
                "body": secret_body,
            })
        assert response.status_code == 200
        history = client.get("/api/history").get_json()["history"]
        assert secret_body not in json.dumps(history)

    def test_database_failure_returns_explicit_error(self, client, clean_db):
        import sqlite3
        with patch("app.requests.post", side_effect=requests.ConnectionError), patch(
            "app.save_scan",
            side_effect=sqlite3.OperationalError("disk unavailable"),
        ):
            response = client.post("/api/analyze", json=LEGITIMATE_EMAIL)
        assert response.status_code == 500
        assert "could not be saved" in response.get_json()["error"]


# ── History endpoint ───────────────────────────────────────────────────────

class TestHistory:
    def test_history_empty_initially(self, client, clean_db):
        res = client.get("/api/history")
        assert res.status_code == 200
        data = res.get_json()
        assert data["count"] == 0
        assert data["history"] == []

    def test_history_contains_scan_after_analyze(self, client, clean_db):
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_PHISHING_RESPONSE)):
            client.post("/api/analyze", json=PHISHING_EMAIL)

        res = client.get("/api/history")
        assert res.status_code == 200
        data = res.get_json()
        assert data["count"] == 1
        scan = data["history"][0]
        assert scan["sender"] == PHISHING_EMAIL["sender"]
        assert scan["subject"] == PHISHING_EMAIL["subject"]
        assert "findings" in scan
        assert isinstance(scan["findings"], list)
        # New columns present
        assert "rule_score" in scan
        assert "ai_contribution" in scan

    def test_delete_scan(self, client, clean_db):
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_PHISHING_RESPONSE)):
            client.post("/api/analyze", json=PHISHING_EMAIL)

        scan_id = client.get("/api/history").get_json()["history"][0]["id"]
        res = client.delete(f"/api/history/{scan_id}")
        assert res.status_code == 200

        history = client.get("/api/history").get_json()
        assert history["count"] == 0

    def test_delete_nonexistent_scan_returns_404(self, client, clean_db):
        res = client.delete("/api/history/999999")
        assert res.status_code == 404
        assert "error" in res.get_json()

    def test_clear_history(self, client, clean_db):
        # Add two scans
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_PHISHING_RESPONSE)):
            client.post("/api/analyze", json=PHISHING_EMAIL)
            client.post("/api/analyze", json=LEGITIMATE_EMAIL)

        res = client.delete("/api/history")
        assert res.status_code == 200
        assert client.get("/api/history").get_json()["count"] == 0


# ── Scoring math ───────────────────────────────────────────────────────────

class TestScoringMath:
    """Unit-style tests for the combined scoring helper in app/__init__.py."""

    def test_ai_contribution_phishing_full_confidence(self):
        from app import _ai_score_contribution
        assert _ai_score_contribution("Likely Phishing", 100) == 40

    def test_ai_contribution_phishing_half_confidence(self):
        from app import _ai_score_contribution
        assert _ai_score_contribution("Likely Phishing", 50) == 20

    def test_ai_contribution_suspicious_full_confidence(self):
        from app import _ai_score_contribution
        assert _ai_score_contribution("Suspicious", 100) == 20

    def test_ai_contribution_legitimate_is_zero(self):
        from app import _ai_score_contribution
        assert _ai_score_contribution("Likely Legitimate", 100) == 0

    def test_ai_contribution_none_verdict_is_zero(self):
        from app import _ai_score_contribution
        assert _ai_score_contribution(None, 80) == 0

    def test_ai_contribution_none_confidence_is_zero(self):
        from app import _ai_score_contribution
        assert _ai_score_contribution("Likely Phishing", None) == 0

    def test_category_from_score_boundaries(self):
        from app import _category_from_score
        assert _category_from_score(0)   == "Low"
        assert _category_from_score(24)  == "Low"
        assert _category_from_score(25)  == "Medium"
        assert _category_from_score(49)  == "Medium"
        assert _category_from_score(50)  == "High"
        assert _category_from_score(74)  == "High"
        assert _category_from_score(75)  == "Critical"
        assert _category_from_score(100) == "Critical"

    def test_rule_contribution_capped_at_60(self, client, clean_db):
        """Even if rules fire heavily, their cap is 60."""
        with patch("app.requests.post",
                   return_value=_mock_ollama_post(OLLAMA_PHISHING_RESPONSE)):
            res = client.post("/api/analyze", json=PHISHING_EMAIL)
        data = res.get_json()
        assert data["rule_contribution"] <= 60
