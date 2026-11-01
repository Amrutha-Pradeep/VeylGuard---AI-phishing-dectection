# VeylGuard — local AI phishing email detector

VeylGuard is an educational Flask web app that combines transparent phishing indicators with an advisory assessment from a locally running Ollama model. It stores scan history in SQLite and does not store the email body.

> **Advisory only:** this is not a production security product. It can miss phishing and flag legitimate mail. Never use its score as proof that an email is safe.

## Features

- Sender, subject and body form with required-field checks, whitespace trimming and size limits.
- Seven documented rule indicators: suspicious links, urgency, sensitive-information requests, suspicious sender-domain tokens, display-name/domain mismatch, generic greetings and attachment lures.
- Ollama JSON analysis with response validation, selected-model status, timeout and unavailable-service handling.
- Explainable 0–100 score, rule/AI contributions, category, rule evidence and AI evidence/recommendations.
- SQLite scan history with search, category filter, findings details, individual deletion and clear-all confirmation.
- Text/JSON report export and a responsive dashboard.
- Email body is not written to the database; URL links are never opened and email is never sent.

## Requirements

- Python 3.11 or later (the tests have also been run with Python 3.13).
- [Ollama for Windows](https://ollama.com/download).
- The `qwen2.5:3b` model (approximately 2 GB; exact disk use depends on Ollama/model version).

## First-time setup (Windows PowerShell)

Open PowerShell in this project folder:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
ollama pull qwen2.5:3b
```

If PowerShell blocks activation, use this only for the current terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Ollama Desktop normally starts its local service automatically. If it is not running, open Ollama from the Start menu. Check the model with:

```powershell
ollama list
```

Start VeylGuard:

```powershell
python run.py
```

Open <http://127.0.0.1:5000> in a browser. Keep the terminal and Ollama running while you use the app. Stop VeylGuard with **Ctrl+C** in its terminal.

## Run it again later

1. Open Ollama Desktop (and confirm `ollama list` includes `qwen2.5:3b`).
2. Open PowerShell in the VeylGuard folder.
3. Activate the existing virtual environment:

   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```

4. Start the server:

   ```powershell
   python run.py
   ```

5. Visit <http://127.0.0.1:5000>. To stop, return to PowerShell and press **Ctrl+C**.

If the terminal says that `ollama` is not recognized, open Ollama Desktop or add its install directory for that terminal:

```powershell
$env:Path += ";$env:LOCALAPPDATA\Programs\Ollama"
ollama list
```

## Configuration

`run.py` loads the optional `.env` file. `.env.example` contains non-secret defaults:

```dotenv
OLLAMA_URL=http://127.0.0.1:11434/api/chat
OLLAMA_MODEL=qwen2.5:3b
OLLAMA_TIMEOUT=90
```

The matching Ollama model must be pulled locally. The app binds to `127.0.0.1:5000`; Flask debug mode is off by default. Never commit `.env` or the local SQLite database. For isolated tests or screenshots, set `VEYLGUARD_DATABASE` to a separate SQLite path.

## Scoring

- Rule findings are added by group using only the strongest finding in each group, avoiding double-counting repeated indicators in that group. The raw rule score is capped at 60 for the combined score.
- `Likely Phishing` AI verdict contributes up to 40 × confidence/100; `Suspicious` contributes up to 20 × confidence/100; `Likely Legitimate` and unavailable AI contribute zero.
- Final score is the sum of the capped rule contribution and AI contribution, clamped to 100.
- Categories: 0–24 Low, 25–49 Medium, 50–74 High, 75–100 Critical.
- AI confidence is the model's self-reported uncertainty estimate; it is not an empirically calibrated probability and is not the final risk score.

These are educational heuristics, not a validated security standard. See [the assignment answers and demo guide](docs/submission.md) for indicator point values, a worked example, limitations and the Q1–Q12 write-up.

## Tests

With the virtual environment active, run:

```powershell
python -m pytest -q
```

Tests mock Ollama, so Ollama does not need to be running to test the app. They cover rules/scoring, suspicious and benign examples, malformed and oversized input, AI failures/invalid output, history, deletion, privacy behavior and database failure. The project tests were verified locally; see the result section in [docs/submission.md](docs/submission.md).

## Screenshots

- Dashboard: [docs/screenshots/dashboard.png](docs/screenshots/dashboard.png)
- Example analysis: [docs/screenshots/analysis-result.png](docs/screenshots/analysis-result.png)

Screenshots use synthetic sample email data only.

## Troubleshooting

- **Ollama offline:** open Ollama Desktop and wait for its local service to start. Rule analysis still works without it.
- **Model missing:** run `ollama pull qwen2.5:3b`; refresh the page.
- **Port 5000 in use:** close the other local app using port 5000, then restart VeylGuard.
- **Dependencies not found:** activate `.venv` and run `python -m pip install -r requirements.txt`.
- **Activation command not found:** use the PowerShell commands above from the project directory; do not make a new environment on every run.
- **History deletion:** use the history controls in the dashboard. The DB is local at `instance/veyguard.sqlite3`.

## Safety and privacy

Use synthetic or explicitly authorized samples. Do not paste confidential messages, automatically follow suspicious links, download attachments or submit credentials. The app sends analyzed content only to the local Ollama HTTP service, but local processing does not guarantee that the host, logs or database are secure. Scan history contains sender, subject and findings; clear it when no longer needed.

## Project structure

```text
app/                 Flask routes, rule engine, Ollama client and SQLite layer
templates/           HTML dashboard
static/              CSS and JavaScript
tests/               pytest unit and integration tests
docs/                Architecture and assignment write-up
docs/screenshots/    Synthetic-data UI screenshots
instance/            Local SQLite database (ignored by Git)
.env.example         Non-secret configuration template
requirements.txt     Python dependencies
run.py               Local development entry point
```

## Repository delivery

### Push this project to GitHub

Create an empty GitHub repository named `ai-phishing-email-detector` (do not initialize it with a README or license), then open PowerShell in this project folder. Review the files before staging; `.env`, `.venv`, caches and the local SQLite database are excluded by `.gitignore`.

For a new local repository:

```powershell
git init
git add .
git status --short
git commit -m "Prepare VeylGuard phishing detection project"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/ai-phishing-email-detector.git
git push -u origin main
```

Replace `YOUR-USERNAME` with your GitHub username and use your actual repository name. If `git remote add` says `origin` already exists, inspect it with `git remote -v`; update the URL only if it is the wrong repository. If the folder is already a Git repository, do not run `git init` again; review `git status`, then commit and push.

GitHub will normally open a browser sign-in through Git Credential Manager. Do not put a password or personal access token in the remote URL, project files, or chat. For a private repository, add the instructor and teammates under GitHub **Settings → Collaborators** and confirm they can view it. Share the repository URL with the instructor/group after pushing.
