import json
import os
import sqlite3
from pathlib import Path

import requests
from flask import Flask, jsonify, render_template, request

from app.ai_analyzer import MODEL_NAME, OLLAMA_URL, analyze_email_with_ai
from app.database import (
    clear_history,
    close_db,
    delete_scan,
    get_db,
    init_db,
    save_scan,
)
from app.detector import analyze_rules, calculate_risk


# ── Scoring helper ─────────────────────────────────────────────────────────

def _ai_score_contribution(ai_verdict, ai_confidence):
    """
    Convert an AI verdict + confidence into 0–40 advisory score points.

    The rule engine contributes up to 60 points (deterministic).
    The AI contributes up to 40 points (advisory, scaled by confidence).
    Both are summed and clamped to 0–100 to produce the final risk score.

    Mapping:
      "Likely Phishing"  → up to 40 pts × (confidence / 100)
      "Suspicious"       → up to 20 pts × (confidence / 100)
      "Likely Legitimate"→  0 pts
      unavailable        →  0 pts
    """
    if not ai_verdict or not isinstance(ai_confidence, int):
        return 0
    try:
        confidence = max(0, min(100, int(ai_confidence)))
    except (TypeError, ValueError):
        return 0

    if ai_verdict == "Likely Phishing":
        max_pts = 40
    elif ai_verdict == "Suspicious":
        max_pts = 20
    else:
        max_pts = 0

    return round(max_pts * confidence / 100)


def _category_from_score(score):
    """Map a 0–100 score to a risk category (matches the brief thresholds)."""
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


# ── App factory ────────────────────────────────────────────────────────────

def create_app(test_config=None):
    """Create and configure the Flask application.

    Pass ``test_config`` (a dict) to override configuration values for
    testing, e.g.::

        app = create_app({"TESTING": True, "DATABASE": ":memory:"})
    """
    project_root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
    )
    app.config["DATABASE"] = str(
        os.getenv(
            "VEYLGUARD_DATABASE",
            str(project_root / "instance" / "veyguard.sqlite3"),
        )
    )
    app.config["MAX_CONTENT_LENGTH"] = 25_600

    if test_config is not None:
        app.config.update(test_config)

    app.teardown_appcontext(close_db)

    with app.app_context():
        init_db()

    @app.errorhandler(413)
    def request_too_large(_error):
        return jsonify({"error": "The request is too large."}), 413

    # ── Routes ────────────────────────────────────────────────────────────

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/api/health")
    def health():
        """Report whether the local Ollama server responds and list models."""
        try:
            response = requests.get(
                f"{OLLAMA_URL.rsplit('/', 1)[0]}/tags", timeout=3
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict) or not isinstance(
                payload.get("models"), list
            ):
                raise ValueError("Invalid Ollama model list")
            models = payload["models"]
            if any(
                not isinstance(model, dict)
                or not isinstance(model.get("name"), str)
                for model in models
            ):
                raise ValueError("Invalid Ollama model entry")
            model_names = [model["name"] for model in models]
            model_available = MODEL_NAME in model_names
            return jsonify({
                "status": "online",
                "models": model_names,
                "active_model": MODEL_NAME,
                "model_available": model_available,
            })
        except (requests.RequestException, ValueError):
            return jsonify({
                "status": "offline",
                "models": [],
                "active_model": MODEL_NAME,
                "model_available": False,
            }), 503

    @app.route("/api/analyze", methods=["POST"])
    def analyze_email():
        """Validate, analyze (rules + AI), combine scores, and save a scan."""
        if not request.is_json:
            return jsonify({"error": "Please submit the email as JSON."}), 415

        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "Invalid request data."}), 400

        sender  = data.get("sender",  "")
        subject = data.get("subject", "")
        body    = data.get("body",    "")
        if not all(isinstance(v, str) for v in (sender, subject, body)):
            return jsonify({"error": "All email fields must contain text."}), 400

        sender, subject, body = sender.strip(), subject.strip(), body.strip()
        if not sender or not subject or not body:
            return jsonify({"error": "Please complete all email fields."}), 400
        if len(sender) > 254:
            return jsonify({"error": "The sender field is too long."}), 400
        if len(subject) > 300:
            return jsonify({"error": "The subject must be 300 characters or fewer."}), 400
        if len(body) > 20_000:
            return jsonify({"error": "The email body must be 20,000 characters or fewer."}), 400

        # ── Rule-based analysis ───────────────────────────────────────────
        findings    = analyze_rules(sender, subject, body)
        rule_result = calculate_risk(findings)
        rule_score_raw = rule_result["score"]           # 0–100 from rules
        rule_contribution = min(60, rule_score_raw)     # capped at 60

        # ── AI analysis ───────────────────────────────────────────────────
        ai_result      = analyze_email_with_ai(sender, subject, body)
        ai_analysis    = ai_result.get("analysis")
        ai_verdict     = None
        ai_confidence  = None
        if isinstance(ai_analysis, dict):
            ai_verdict    = ai_analysis.get("verdict")
            ai_confidence = ai_analysis.get("confidence")

        # ── Combined scoring ──────────────────────────────────────────────
        ai_contribution = _ai_score_contribution(ai_verdict, ai_confidence)
        final_score     = min(100, rule_contribution + ai_contribution)
        final_category  = _category_from_score(final_score)

        # ── Persist ───────────────────────────────────────────────────────
        try:
            save_scan(
                sender=sender,
                subject=subject,
                score=final_score,
                rule_score=rule_score_raw,
                ai_contribution=ai_contribution,
                category=final_category,
                findings=json.dumps(findings),
                ai_verdict=ai_verdict,
                ai_confidence=ai_confidence,
            )
        except sqlite3.Error:
            app.logger.exception("Failed to save scan history")
            return jsonify({
                "error": "The analysis completed, but the scan could not be saved."
            }), 500

        return jsonify({
            "sender":           sender,
            "subject":          subject,
            # Combined score (primary)
            "score":            final_score,
            "category":         final_category,
            # Score breakdown (for transparency / Q5)
            "rule_score":       rule_score_raw,
            "rule_contribution": rule_contribution,
            "ai_contribution":  ai_contribution,
            "scoring_method": (
                "Rule engine (max 60 pts, deterministic) + "
                "AI verdict × confidence (max 40 pts, advisory). "
                "Score capped at 100. "
                "Thresholds: 0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical."
            ),
            # Detail lists
            "breakdown": rule_result["breakdown"],
            "evidence":  rule_result["evidence"],
            "findings":  findings,
            # AI
            "ai_analysis": ai_analysis,
            "ai_error":    ai_result.get("error"),
            "analysis_type": "rules_and_ai",
            "notice": (
                "The risk score is advisory only. "
                "Rules supply up to 60 deterministic points; "
                "the local AI model supplies up to 40 advisory points. "
                "Neither result guarantees an email is safe or malicious. "
                "Verify suspicious requests through a trusted channel."
            ),
        })

    @app.route("/api/history", methods=["GET"])
    def scan_history():
        """Return the latest 100 scans, newest first."""
        rows = get_db().execute(
            """
            SELECT id, timestamp, sender, subject, score,
                   rule_score, ai_contribution, category,
                   findings, ai_verdict, ai_confidence
            FROM scan_history
            ORDER BY id DESC
            LIMIT 100
            """
        ).fetchall()

        history = []
        for row in rows:
            item = dict(row)
            try:
                item["findings"] = json.loads(item["findings"])
            except (json.JSONDecodeError, TypeError):
                item["findings"] = []
            history.append(item)
        return jsonify({"count": len(history), "history": history})

    @app.route("/api/history/<int:scan_id>", methods=["DELETE"])
    def remove_scan(scan_id):
        """Delete one saved scan."""
        if not delete_scan(scan_id):
            return jsonify({"error": "Scan not found."}), 404
        return jsonify({"message": "Scan deleted successfully."})

    @app.route("/api/history", methods=["DELETE"])
    def remove_all_scans():
        """Delete all saved scans."""
        clear_history()
        return jsonify({"message": "Scan history cleared successfully."})

    return app
