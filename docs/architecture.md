# VeylGuard — System Architecture

## Overview

VeylGuard is a local-first web application. All processing happens on the
user's own machine. No email content is transmitted to any external server.

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER'S BROWSER                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │  HTML/CSS/JavaScript (static/)                          │   │
│  │  • Email input form  (sender, subject, body)            │   │
│  │  • Results dashboard (score ring, findings, AI panel)   │   │
│  │  • Scan history      (search, filter, delete)           │   │
│  │  • Export            (copy / download JSON / .txt)      │   │
│  └────────────────────────┬────────────────────────────────┘   │
│                           │  HTTP (fetch API)                  │
└───────────────────────────┼─────────────────────────────────────┘
                            │  localhost:5000
┌───────────────────────────┼─────────────────────────────────────┐
│                    FLASK BACKEND  (run.py)                       │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Routes  (app/__init__.py)                               │   │
│  │  GET  /                → serves index.html               │   │
│  │  GET  /api/health      → Ollama connectivity check       │   │
│  │  POST /api/analyze     → main analysis pipeline          │   │
│  │  GET  /api/history     → list saved scans                │   │
│  │  DELETE /api/history   → clear all scans                 │   │
│  │  DELETE /api/history/<id> → delete one scan              │   │
│  └────────┬─────────────────────────┬───────────────────────┘   │
│           │                         │                           │
│  ┌────────▼──────────────┐ ┌────────▼──────────────────────┐   │
│  │  Rule Engine          │ │  AI Analyzer                  │   │
│  │  (app/detector.py)    │ │  (app/ai_analyzer.py)         │   │
│  │                       │ │                               │   │
│  │  7 indicators:        │ │  POST /api/chat → Ollama      │   │
│  │  1. Suspicious URL    │ │  Model: qwen2.5:3b            │   │
│  │  2. Urgency phrases   │ │  Format: JSON                 │   │
│  │  3. Sensitive info    │ │  Timeout: 90 s                │   │
│  │  4. Sender domain     │ │                               │   │
│  │  5. Display name      │ │  Returns:                     │   │
│  │     mismatch          │ │  • verdict                    │   │
│  │  6. Generic greeting  │ │  • confidence (0–100)         │   │
│  │  7. Attachment lure   │ │  • reasons []                 │   │
│  │                       │ │  • evidence snippets []       │   │
│  │                       │ │  • recommendations []         │   │
│  │  → raw score 0–100    │ │  • uncertainty                │   │
│  │  → capped at 60 pts   │ │  → advisory 0–40 pts          │   │
│  └────────┬──────────────┘ └────────┬──────────────────────┘   │
│           │                         │                           │
│  ┌────────▼─────────────────────────▼───────────────────────┐   │
│  │  Combined Scorer  (app/__init__.py)                       │   │
│  │                                                           │   │
│  │  final_score = min(100,                                   │   │
│  │      min(60, rule_score) + ai_contribution)               │   │
│  │                                                           │   │
│  │  Categories: 0–24 Low | 25–49 Medium                     │   │
│  │              50–74 High | 75–100 Critical                 │   │
│  └────────┬──────────────────────────────────────────────────┘   │
│           │                                                      │
│  ┌────────▼──────────────────────────────────────────────────┐   │
│  │  Database Layer  (app/database.py)                        │   │
│  │  SQLite — instance/veyguard.sqlite3                       │   │
│  │                                                           │   │
│  │  scan_history table:                                      │   │
│  │  id | timestamp | sender | subject | score               │   │
│  │  rule_score | ai_contribution | category                 │   │
│  │  findings (JSON) | ai_verdict | ai_confidence            │   │
│  │                                                           │   │
│  │  Note: email body is NEVER stored.                        │   │
│  └───────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
                            │  localhost:11434
┌───────────────────────────┼─────────────────────────────────────┐
│            OLLAMA SERVICE (local process)                        │
│                                                                  │
│   Model: qwen2.5:3b                                              │
│   API:   http://127.0.0.1:11434/api/chat                        │
│   Runs entirely on the user's hardware — no external requests.  │
└─────────────────────────────────────────────────────────────────┘
```

## Component Responsibilities

| Component | File(s) | Responsibility |
|---|---|---|
| **Frontend** | `templates/index.html`, `static/css/style.css`, `static/js/app.js` | Renders the dashboard, submits forms via `fetch`, displays results, exports reports |
| **Flask backend** | `app/__init__.py`, `run.py` | Validates input, orchestrates rule engine + AI, combines scores, saves to DB, serves JSON API |
| **Rule engine** | `app/detector.py` | 7 deterministic phishing indicator checks; returns findings list + raw 0–100 score |
| **AI analyzer** | `app/ai_analyzer.py` | Sends structured prompt to local Ollama; validates verdict, confidence, reasons, quoted evidence and recommendations |
| **Combined scorer** | `app/__init__.py` | Caps rule score at 60; maps AI verdict×confidence to 0–40; sums to final 0–100 score |
| **Database** | `app/database.py`, `instance/veyguard.sqlite3` | Stores timestamp, sender, subject, scores, category and findings; uses parameterized inserts/deletes |
| **Ollama service** | External local process | Hosts `qwen2.5:3b`; processes the prompt and returns JSON; never sends data externally |

## Request Flow (Step-by-Step)

```
1. User fills form → JS sends POST /api/analyze (JSON)
2. Flask validates: field presence, types, length limits
3. Rule engine scans sender + subject + body for 7 indicators
4. AI analyzer sends prompt to Ollama; validates returned JSON
5. Combined scorer: min(60, rule_score) + ai_contribution → final_score
6. Database: INSERT into scan_history (body NOT stored)
7. Flask returns JSON: score, breakdown, findings, ai_analysis
8. JS animates score ring, populates findings, shows AI panel
9. JS auto-refreshes history section
```

## Data Flow — Privacy Notes

- The email body is sent to Flask **in memory** and to Ollama (local only).
- The body is **never written to disk** (not in SQLite, not in logs).
- The SQLite database stores: timestamp, sender, subject, score, category and findings summary; it does not store the body.
- Ollama runs on localhost — no email content leaves the machine.
- The dashboard uses system fonts and local static assets; it does not fetch third-party fonts or scripts.
