/* ════════════════════════════════════════════════════════════════
   VeylGuard — Frontend Logic
   ════════════════════════════════════════════════════════════════ */

"use strict";

// ── Element refs ───────────────────────────────────────────────────────────
const statusText        = document.getElementById("ollama-status");
const statusDot         = document.getElementById("status-dot");
const aiFeatureState    = document.getElementById("ai-feature-state");

const emailForm         = document.getElementById("email-form");
const emailBody         = document.getElementById("body");
const charCount         = document.getElementById("char-count");
const formMessage       = document.getElementById("form-message");
const analyzeButton     = document.getElementById("analyze-button");
const btnLabel          = document.getElementById("btn-label");
const btnSpinner        = document.getElementById("btn-spinner");
const btnArrow          = document.getElementById("btn-arrow");

const resultsSection    = document.getElementById("results");
const riskScore         = document.getElementById("risk-score");
const riskCategory      = document.getElementById("risk-category");
const ringFill          = document.getElementById("ring-fill");
const scoreRingWrap     = document.querySelector(".score-ring-wrap");
const scorePills        = document.getElementById("score-pills");
const pillRule          = document.getElementById("pill-rule");
const pillAi            = document.getElementById("pill-ai");
const pillTotal         = document.getElementById("pill-total");
const findingsList      = document.getElementById("findings-list");
const breakdownList     = document.getElementById("breakdown-list");
const analysisNotice    = document.getElementById("analysis-notice");

const aiVerdictEl       = document.getElementById("ai-verdict");
const aiConfidenceEl    = document.getElementById("ai-confidence");
const aiVerdictBadge    = document.getElementById("ai-verdict-badge");
const aiReasons         = document.getElementById("ai-reasons");
const aiRecommendations = document.getElementById("ai-recommendations");
const aiUncertainty     = document.getElementById("ai-uncertainty");

const copyReportBtn     = document.getElementById("copy-report");
const downloadJsonBtn   = document.getElementById("download-json");
const downloadTxtBtn    = document.getElementById("download-txt");
const exportMessage     = document.getElementById("export-message");

const historyList       = document.getElementById("history-list");
const historyMessage    = document.getElementById("history-message");
const historySearch     = document.getElementById("history-search");
const historyFilter     = document.getElementById("history-filter");
const refreshHistoryBtn = document.getElementById("refresh-history");
const clearHistoryBtn   = document.getElementById("clear-history");

const RING_CIRCUMFERENCE = 314.16; // 2 * π * 50

let savedHistory  = [];
let lastScanData  = null;   // holds the last API response for export

// ── Helpers ────────────────────────────────────────────────────────────────

const categoryClass     = (cat) => `risk-${(cat || "").toLowerCase()}`;
const categoryCardClass = (cat) => `cat-${(cat || "").toLowerCase()}`;

function addListItem(list, text) {
    const li = document.createElement("li");
    li.textContent = text;
    list.appendChild(li);
}

// ── Ollama health check ────────────────────────────────────────────────────

async function checkOllamaStatus() {
    try {
        const res  = await fetch("/api/health");
        const data = await res.json();
        if (!res.ok || data.status !== "online") throw new Error("offline");

        const modelLabel = data.active_model
            ? ` · ${data.active_model}`
            : "";
        if (data.model_available === false) {
            statusText.textContent = `Ollama online · model not pulled${modelLabel}`;
            statusDot.className = "status-dot offline";
            aiFeatureState.textContent = "MODEL MISSING";
            aiFeatureState.classList.add("offline");
        } else {
            statusText.textContent = `Local AI online${modelLabel}`;
            statusDot.className = "status-dot online";
            aiFeatureState.textContent = "ONLINE";
            aiFeatureState.classList.remove("offline");
        }
    } catch {
        statusText.textContent     = "Local AI offline";
        statusDot.className        = "status-dot offline";
        aiFeatureState.textContent = "OFFLINE";
        aiFeatureState.classList.add("offline");
    }
}

// ── Character counter ──────────────────────────────────────────────────────

emailBody.addEventListener("input", () => {
    charCount.textContent = `${emailBody.value.length.toLocaleString()} / 20,000`;
});

// ── Score ring animation ───────────────────────────────────────────────────

function animateRing(score, category) {
    const catClass = categoryClass(category);
    scoreRingWrap.classList.remove("risk-critical", "risk-high", "risk-medium", "risk-low");
    scoreRingWrap.classList.add(catClass);

    const filled = RING_CIRCUMFERENCE * (score / 100);
    const offset = RING_CIRCUMFERENCE - filled;

    // Double rAF ensures the transition replays on repeated submissions
    ringFill.style.transition        = "none";
    ringFill.style.strokeDashoffset  = RING_CIRCUMFERENCE;
    requestAnimationFrame(() => {
        requestAnimationFrame(() => {
            ringFill.style.transition =
                "stroke-dashoffset .9s cubic-bezier(.4,0,.2,1), stroke .4s";
            ringFill.style.strokeDashoffset = offset;
        });
    });
}

// ── Score breakdown pills ──────────────────────────────────────────────────

function updateScorePills(data) {
    const rc  = data.rule_contribution  ?? 0;
    const ai  = data.ai_contribution    ?? 0;
    const tot = data.score              ?? 0;

    pillRule.textContent  = `Rule: ${rc}/60`;
    pillAi.textContent    = `AI: ${ai}/40`;
    pillTotal.textContent = `Total: ${tot}/100`;
    scorePills.hidden = false;
}

// ── Render findings ────────────────────────────────────────────────────────

function displayFindings(findings) {
    findingsList.replaceChildren();
    if (!findings || findings.length === 0) {
        addListItem(
            findingsList,
            "No rule-based indicators were detected. This does not guarantee the email is safe."
        );
        return;
    }
    findings.forEach((f) => addListItem(findingsList, `${f.title}: ${f.evidence}`));
}

function displayBreakdown(breakdown) {
    breakdownList.replaceChildren();
    if (!breakdown || breakdown.length === 0) {
        addListItem(breakdownList, "No risk points were added.");
        return;
    }
    breakdown.forEach((item) =>
        addListItem(breakdownList, `${item.group}: +${item.points} pts`)
    );
}

// ── Render AI analysis ─────────────────────────────────────────────────────

function verdictBadgeClass(verdict) {
    if (!verdict) return "unavailable";
    const v = verdict.toLowerCase();
    if (v.includes("phishing"))   return "phishing";
    if (v.includes("suspicious")) return "suspicious";
    if (v.includes("legitimate")) return "legitimate";
    return "unavailable";
}

function displayAIAnalysis(ai, aiError) {
    aiReasons.replaceChildren();
    const aiEvidence = document.getElementById("ai-evidence");
    aiEvidence.replaceChildren();
    aiRecommendations.replaceChildren();

    if (!ai) {
        aiVerdictEl.textContent    = "Unavailable";
        aiConfidenceEl.textContent = "—";
        aiVerdictBadge.className   = "verdict-badge unavailable";
        aiVerdictBadge.textContent = "UNAVAILABLE";
        addListItem(aiReasons, aiError || "The local AI assessment could not be completed.");
        addListItem(aiEvidence, "No validated AI evidence is available.");
        addListItem(aiRecommendations, "Verify unexpected requests through a trusted channel.");
        aiUncertainty.textContent  = "Only the rule-based score is available for this scan.";
        return;
    }

    aiVerdictEl.textContent    = ai.verdict;
    aiConfidenceEl.textContent = `${ai.confidence}%`;
    aiVerdictBadge.className   = `verdict-badge ${verdictBadgeClass(ai.verdict)}`;
    aiVerdictBadge.textContent = (ai.verdict || "").toUpperCase();

    (ai.reasons || []).forEach((r) => addListItem(aiReasons, r));
    if (!ai.reasons?.length) addListItem(aiReasons, "No additional reasoning provided.");

    (ai.evidence || []).forEach((item) => addListItem(aiEvidence, item));
    if (!ai.evidence?.length) addListItem(aiEvidence, "The model supplied no evidence snippets.");

    (ai.recommendations || []).forEach((r) => addListItem(aiRecommendations, r));
    if (!ai.recommendations?.length)
        addListItem(aiRecommendations, "Verify unexpected requests through a trusted channel.");

    aiUncertainty.textContent = ai.uncertainty || "The AI may make mistakes.";
}

// ── Export / report ────────────────────────────────────────────────────────

function buildTextReport(data) {
    const line  = "═".repeat(56);
    const dline = "─".repeat(56);
    const ts    = new Date().toLocaleString();
    const fmt   = (arr) =>
        (arr && arr.length > 0 ? arr : ["None"]).map((s) => `  • ${s}`).join("\n");

    return [
        line,
        "  VeylGuard — Phishing Detection Report",
        line,
        `  Date:     ${ts}`,
        `  Sender:   ${data.sender}`,
        `  Subject:  ${data.subject}`,
        "",
        `  Combined Risk Score : ${data.score}/100  (${data.category})`,
        `  Rule contribution   : ${data.rule_contribution ?? "?"}/60  (raw rule score: ${data.rule_score ?? "?"})`,
        `  AI contribution     : ${data.ai_contribution ?? "?"}/40`,
        "",
        dline,
        "  SCORING METHOD",
        dline,
        `  ${data.scoring_method || "Rule engine (max 60 pts) + AI advisory (max 40 pts)."}`,
        "",
        dline,
        "  DETECTED INDICATORS",
        dline,
        fmt((data.findings || []).map((f) => `${f.title}: ${f.evidence}`)),
        "",
        dline,
        "  RISK BREAKDOWN",
        dline,
        fmt((data.breakdown || []).map((b) => `${b.group}: +${b.points} pts`)),
        "",
        dline,
        "  AI ASSESSMENT (LOCAL OLLAMA)",
        dline,
        `  Verdict:    ${data.ai_analysis?.verdict    ?? "Unavailable"}`,
        `  Confidence: ${data.ai_analysis?.confidence != null ? data.ai_analysis.confidence + "%" : "—"}`,
        "",
        "  AI Reasoning:",
        fmt(data.ai_analysis?.reasons),
        "",
        "  AI Evidence:",
        fmt(data.ai_analysis?.evidence),
        "",
        "  Recommendations:",
        fmt(data.ai_analysis?.recommendations),
        "",
        `  Uncertainty: ${data.ai_analysis?.uncertainty ?? "AI assessment was unavailable."}`,
        "",
        dline,
        "  ADVISORY NOTICE",
        dline,
        `  ${data.notice || ""}`,
        "",
        line,
        "  This report is advisory only. Do not treat it as a security guarantee.",
        line,
    ].join("\n");
}

function triggerDownload(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function showExportMessage(msg) {
    exportMessage.textContent = msg;
    setTimeout(() => { exportMessage.textContent = ""; }, 3000);
}

copyReportBtn.addEventListener("click", async () => {
    if (!lastScanData) return;
    try {
        await navigator.clipboard.writeText(buildTextReport(lastScanData));
        showExportMessage("✓ Report copied to clipboard.");
    } catch {
        showExportMessage("⚠ Clipboard access denied. Try downloading instead.");
    }
});

downloadJsonBtn.addEventListener("click", () => {
    if (!lastScanData) return;
    // Strip the body from the exported JSON (privacy)
    const exportable = { ...lastScanData, body: "[not stored]" };
    triggerDownload(
        JSON.stringify(exportable, null, 2),
        `vg-scan-${Date.now()}.json`,
        "application/json"
    );
    showExportMessage("✓ JSON report downloaded.");
});

downloadTxtBtn.addEventListener("click", () => {
    if (!lastScanData) return;
    triggerDownload(
        buildTextReport(lastScanData),
        `vg-scan-${Date.now()}.txt`,
        "text/plain"
    );
    showExportMessage("✓ Text report downloaded.");
});

// ── Form submission ────────────────────────────────────────────────────────

emailForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    formMessage.textContent = "";

    analyzeButton.disabled  = true;
    btnLabel.textContent    = "Analyzing…";
    btnSpinner.hidden       = false;
    btnArrow.hidden         = true;

    const payload = {
        sender:  document.getElementById("sender").value,
        subject: document.getElementById("subject").value,
        body:    emailBody.value,
    };

    try {
        const res  = await fetch("/api/analyze", {
            method:  "POST",
            headers: { "Content-Type": "application/json" },
            body:    JSON.stringify(payload),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Analysis failed.");

        // Store for export (include sender/subject from payload)
        lastScanData = { ...data, sender: payload.sender, subject: payload.subject };

        // Score + ring
        riskScore.textContent    = data.score;
        riskCategory.textContent = data.category;
        riskCategory.className   = `risk-category ${categoryClass(data.category)}`;
        animateRing(data.score, data.category);
        updateScorePills(data);

        // Lists
        displayFindings(data.findings);
        displayBreakdown(data.breakdown);
        displayAIAnalysis(data.ai_analysis, data.ai_error);
        analysisNotice.textContent = data.notice || "";

        // Reveal + scroll
        resultsSection.hidden = false;
        setTimeout(() => {
            resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 80);

        await loadHistory();

    } catch (err) {
        formMessage.textContent = err.message || "Could not analyze this email.";
    } finally {
        analyzeButton.disabled = false;
        btnLabel.textContent   = "Analyze email";
        btnSpinner.hidden      = true;
        btnArrow.hidden        = false;
    }
});

// ── History rendering ──────────────────────────────────────────────────────

function displayHistory() {
    historyList.replaceChildren();
    const term     = historySearch.value.trim().toLowerCase();
    const category = historyFilter.value;

    const filtered = savedHistory.filter((scan) => {
        const sender  = (scan.sender  || "").toLowerCase();
        const subject = (scan.subject || "").toLowerCase();
        return (sender.includes(term) || subject.includes(term))
            && (category === "all" || scan.category === category);
    });

    if (filtered.length === 0) {
        const empty = document.createElement("div");
        empty.className   = "empty-state";
        empty.textContent = savedHistory.length === 0
            ? "No scans saved yet. Analyze an email above to see it here."
            : "No scans match your current search or filter.";
        historyList.appendChild(empty);
        historyMessage.textContent = "0 scans displayed.";
        return;
    }

    historyMessage.textContent =
        `${filtered.length} scan${filtered.length !== 1 ? "s" : ""} displayed.`;

    filtered.forEach((scan) => {
        const catClass = categoryCardClass(scan.category);
        const card     = document.createElement("article");
        card.className = `history-card ${catClass}`;

        const badge = document.createElement("span");
        badge.className   = `card-badge ${catClass}`;
        badge.textContent = scan.category || "Unknown";

        const heading = document.createElement("h3");
        heading.appendChild(document.createTextNode(scan.subject || "(No subject)"));
        heading.appendChild(badge);

        const sender = document.createElement("p");
        sender.textContent = `From: ${scan.sender}`;

        const score = document.createElement("p");
        score.className   = `history-score ${catClass}`;
        score.textContent = `Risk: ${scan.score}/100 — ${scan.category}`;

        // Show rule/AI breakdown if available
        if (scan.rule_score != null || scan.ai_contribution != null) {
            const breakdown = document.createElement("p");
            breakdown.style.cssText = "color: #5a6e88; font-size: 10px; margin: 3px 0;";
            breakdown.textContent =
                `Rule: ${scan.rule_score ?? "?"} · AI: +${scan.ai_contribution ?? "?"} pts`;
            card.append(heading, sender, score, breakdown);
        } else {
            card.append(heading, sender, score);
        }

        const aiInfo = document.createElement("p");
        aiInfo.textContent = scan.ai_verdict
            ? `AI: ${scan.ai_verdict} (${scan.ai_confidence != null ? scan.ai_confidence + "%" : "n/a"})`
            : "AI: Unavailable";

        const timestamp = document.createElement("p");
        timestamp.textContent = `Scanned: ${scan.timestamp}`;

        // Findings toggle
        const details = document.createElement("ul");
        details.hidden = true;
        (scan.findings || []).forEach((f) => addListItem(details, `${f.title}: ${f.evidence}`));
        if (details.children.length === 0)
            addListItem(details, "No rule-based indicators detected.");

        const detailsBtn = document.createElement("button");
        detailsBtn.className   = "button button-secondary";
        detailsBtn.type        = "button";
        detailsBtn.textContent = "View findings";
        detailsBtn.addEventListener("click", () => {
            details.hidden     = !details.hidden;
            detailsBtn.textContent = details.hidden ? "View findings" : "Hide findings";
        });

        const deleteBtn = document.createElement("button");
        deleteBtn.className   = "button button-danger";
        deleteBtn.type        = "button";
        deleteBtn.textContent = "Delete";
        deleteBtn.addEventListener("click", async () => {
            if (!window.confirm("Delete this scan? This cannot be undone.")) return;
            deleteBtn.disabled = true;
            try {
                const res  = await fetch(`/api/history/${scan.id}`, { method: "DELETE" });
                const data = await res.json();
                if (!res.ok) throw new Error(data.error || "Could not delete scan.");
                await loadHistory();
            } catch (err) {
                historyMessage.textContent = err.message || "Could not delete scan.";
                deleteBtn.disabled = false;
            }
        });

        const actions = document.createElement("div");
        actions.className = "card-actions";
        actions.append(detailsBtn, deleteBtn);

        card.append(aiInfo, timestamp, actions, details);
        historyList.appendChild(card);
    });
}

// ── Load history from API ──────────────────────────────────────────────────

async function loadHistory() {
    historyMessage.textContent = "Loading scan history…";
    try {
        const res  = await fetch("/api/history");
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Could not load scan history.");
        savedHistory = Array.isArray(data.history) ? data.history : [];
        displayHistory();
    } catch (err) {
        historyList.replaceChildren();
        historyMessage.textContent = err.message || "Failed to load scan history.";
    }
}

// ── Event listeners ────────────────────────────────────────────────────────

historySearch.addEventListener("input",  displayHistory);
historyFilter.addEventListener("change", displayHistory);
refreshHistoryBtn.addEventListener("click", loadHistory);

clearHistoryBtn.addEventListener("click", async () => {
    if (!window.confirm("Delete ALL saved scan history? This cannot be undone.")) return;
    clearHistoryBtn.disabled = true;
    try {
        const res  = await fetch("/api/history", { method: "DELETE" });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Could not clear history.");
        savedHistory = [];
        displayHistory();
        historyMessage.textContent = data.message || "Scan history cleared.";
    } catch (err) {
        historyMessage.textContent = err.message || "Failed to clear history.";
    } finally {
        clearHistoryBtn.disabled = false;
    }
});

// ── Init ───────────────────────────────────────────────────────────────────
checkOllamaStatus();
loadHistory();
