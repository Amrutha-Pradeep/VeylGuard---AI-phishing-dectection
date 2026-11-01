# VeylGuard — assignment answers and demonstration guide

This write-up describes the current implementation. It is an educational prototype; scores and model outputs are advisory.

## Q1 — Problem definition

Phishing is a deceptive message intended to persuade a recipient to disclose sensitive information, transfer money, or interact with a harmful link or attachment. VeylGuard accepts sender, subject and body text and highlights selected warning signs using deterministic rules and a local language model.

**Intended users:** students and demonstrators learning about email security and explainable detection.

**Scope:** manual analysis of one pasted email at a time; it does not connect to a mailbox, inspect headers/authentication records, fetch URLs or attachments, or block delivery.

**Limitations:**
1. Phrase and domain heuristics can miss novel attacks and create false positives.
2. The local model can hallucinate, misclassify, or provide uncalibrated confidence; rules and AI scores are not validated against a representative dataset.
3. Sender display names are user-provided text, not authenticated email headers; no SPF, DKIM or DMARC validation is performed.
4. It does not inspect attachment contents, redirects, page behavior, image-only email, or full MIME/header metadata.
5. Local storage and Ollama reduce external transmission but do not protect a compromised or shared computer.

## Q2 — Architecture

See [architecture.md](architecture.md) for the architecture diagram and request flow.

- **Browser:** HTML/CSS/JavaScript form, score/results dashboard, history controls and report exports.
- **Flask backend:** validates content type, field types, required values and size limits; calls the rule engine and Ollama client; combines scores and serves JSON routes.
- **Rule engine:** deterministic indicators with evidence and grouped point contributions.
- **Ollama:** local `/api/chat` service returns structured JSON; output is validated before rendering.
- **SQLite:** parameterized inserts/deletes store timestamp, sender, subject, score, category and findings; the full body is not persisted.

## Q3 — Ollama integration

`GET /api/health` requests the Ollama tags endpoint with a short timeout and reports online/offline state, the configured model and whether it is installed. `POST /api/analyze` sends a JSON-only prompt to the configured local `/api/chat` URL with a configurable timeout. The response is checked for an allowed verdict, integer confidence in 0–100, string arrays for reasons/evidence/recommendations, and string uncertainty. Timeouts, connection failures and invalid output produce a useful advisory error while retaining rule-based results.

Default model: `qwen2.5:3b`; install it using `ollama pull qwen2.5:3b`. Configuration is in `.env.example`.

## Q4 — Detection logic and duplicate handling

The analyzer checks seven indicators:

| Indicator | Safe synthetic example | Raw points |
|---|---|---:|
| Suspicious URL traits | `http://192.0.2.10/login` or `https://bit.ly/example` | 20 |
| Urgency/threat | “Act now or access will be suspended” | 10 |
| Sensitive-data request | “Reply with your password or OTP” | 20 |
| Suspicious sender-domain token | `notice@secure-update-example.test` | 10 |
| Brand/display-name mismatch | `PayPal <notice@unrelated-example.test>` | 25 |
| Generic greeting | “Dear customer” | 5 |
| Attachment lure | “Open the attached invoice” | 15 |

These examples are synthetic and use reserved/example domains. Rule points are grouped as URL, urgency, sensitive, sender, social and attachment. The strongest finding in each group is counted once; for example, sender-domain tokens and brand mismatch are not added together. The combined rule contribution is capped at 60.

## Q5 — Risk score

1. Add the maximum points in each rule group; cap the result at 60.
2. AI points are `round(40 × confidence/100)` for “Likely Phishing”, `round(20 × confidence/100)` for “Suspicious”, and zero for “Likely Legitimate” or unavailable AI.
3. Add both contributions and clamp to 100.
4. Label: 0–24 Low; 25–49 Medium; 50–74 High; 75–100 Critical.

**Worked example:** one suspicious URL (20), urgency language (10), and sensitive request (20) gives 50 raw rule points (50 rule contribution). A “Likely Phishing” model verdict at 75 confidence contributes 30. Final score = 80, **Critical**.

The confidence is the local model's self-reported confidence, not a measured probability. The risk score is an application-defined evidence-weighted heuristic, not confidence and not a guarantee.

## Q6 — Web dashboard

The dashboard collects sender, subject and body; displays the combined score/category, rule and AI contributions, rule indicators/evidence, AI verdict/confidence/evidence/reasons/recommendations, uncertainty and advisory notice. It shows model status, loading/error states, and a responsive history section. User-controlled text is inserted using `textContent`/text nodes, not HTML injection.

## Q7 — History and database

SQLite `scan_history` holds an auto-increment id, local timestamp, sender, subject, score, rule and AI contributions, category, findings JSON, AI verdict and confidence. Inserts and deletion use SQLite parameter placeholders. History is capped to the latest 100 results and supports sender/subject search, client-side category filtering, per-result finding details, individual deletion and clear-all confirmation. The full email body is not saved.

## Q8 — Security and privacy

- Input is required, trimmed, type checked, and limited (sender 254, subject 300, body 20,000 characters); an HTTP request-size cap is also configured.
- The frontend renders data as text. No suspicious URL is fetched/opened and no email is sent.
- SQLite statements use bound parameters.
- Email body is processed in memory and sent to the configured local Ollama service; it is not stored in history or explicitly logged.
- Sender, subject and findings remain in local history until deleted. The host/database is not encrypted by this educational app.
- Local-first processing does not secure a compromised computer; avoid real confidential mail in demonstrations.

## Q9 — Testing

Run `python -m pytest -q`. Ollama HTTP calls are mocked for repeatable integration tests. The suite exercises suspicious, likely legitimate and ambiguous rule patterns, malformed JSON, wrong-type/oversized requests, whitespace normalization, AI unavailable/timeout/invalid JSON and invalid schema/evidence, scoring/category boundaries, history/deletion, no body persistence, and an explicit database write failure.

| Test scenario | Expected behavior | Actual verification |
|---|---|---|
| Synthetic phishing email | Findings and nonzero elevated score | Covered by passing unit/integration tests |
| Ordinary benign email | No rule indicators and Low score for benign AI verdict | Covered by passing unit/integration tests |
| Ambiguous email | One weak attachment reference gives one low-weight indicator | Covered by passing unit test |
| Malformed, missing, wrong-type or oversized input | JSON validation error; no scan persisted | Covered by passing integration tests |
| Ollama unavailable/timeout | Rule-only result plus clear AI error | Covered by passing integration tests |
| Invalid AI JSON/schema | Reject AI result; retain rule findings | Covered by passing integration tests |
| Malformed Ollama model list | Report Ollama as offline with status payload | Covered by passing integration test |
| SQLite write failure | Explicit 500 JSON error and server log | Covered by passing integration test |
| Email body privacy | Body absent from history | Covered by passing integration test |

**Latest local run:** `python -m pytest -q` — 65 tests passed.

## Q10 — GitHub delivery

The project has a README, requirements, `.env.example`, `.gitignore`, architecture documentation, tests, and screenshots. Before submission, the project owner must create or select the GitHub repository, push the source and verify the instructor/group can access it. This checkout did not include a Git remote or GitHub destination, so no repository URL or share access can be confirmed here. Do not push `.env`, `.venv`, caches or `instance/veyguard.sqlite3`.

## Q11 — Demonstration and viva

1. On a clean machine, follow the README first-time setup, install Ollama and pull `qwen2.5:3b`.
2. Start Ollama and VeylGuard; show `/api/health` status and the dashboard.
3. Analyze synthetic phishing-like and benign examples.
4. Explain the triggered indicators, grouped rule score, AI contribution and thresholds.
5. Show history search/filter/details, report download, and confirmed deletion.
6. Stop the app and explain the local database location, setup commands and limitations.

Suggested synthetic suspicious sample:

```text
Sender: PayPal <notice@unrelated-example.test>
Subject: URGENT — verify your account
Body: Dear customer, act now or access will be suspended. Reply with your OTP.
      Visit http://192.0.2.10/login
```

Suggested benign sample:

```text
Sender: sam@example.test
Subject: Lunch tomorrow?
Body: Hi Sam, are we still meeting at noon tomorrow?
```

Do not open or visit sample URLs; the app only analyzes their text.

## Q12 — Reflection and future work

Two key limitations are heuristic rules that can over/under-flag messages and uncalibrated model judgments; the app also lacks authenticated headers and attachment/link inspection. False positives can come from legitimate urgent notices or benign brand mentions; false negatives can come from novel wording, compromised legitimate accounts or hidden content.

Realistic improvements:
1. Evaluate on an authorized, labeled dataset and calibrate thresholds while tracking precision/recall.
2. Add safe header parsing and SPF/DKIM/DMARC result display from trusted, user-provided source data.
3. Add optional, user-consented export/retention controls and stronger local database protection.

## Submission checklist

- [x] Working Flask application and source code
- [x] Setup/run and test instructions in README
- [x] Architecture diagram and request flow
- [x] Q1–Q12 write-up and limitations
- [x] Automated tests with mocked Ollama
- [x] Screenshots captured from the final running UI using synthetic data
- [ ] GitHub push, repository URL and instructor/group access verified by project owner
