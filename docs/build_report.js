// Generates the TriageDesk capstone report (.docx) — Approach 1 (Practical),
// covering all 8 phases of the IT Project 1 brief.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, TableOfContents,
  Table, TableRow, TableCell, WidthType, BorderStyle, AlignmentType,
  ShadingType, PageBreak, LevelFormat,
} = require("docx");

const CW = 9360;
const NAVY = "16263a", ACCENT = "2f6fb0", GREY = "666666";

const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 140 }, children: [new TextRun({ text: t, bold: true, color: NAVY })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 100 }, children: [new TextRun({ text: t, bold: true, color: ACCENT })] });
const P = (t, opts = {}) => new Paragraph({ spacing: { after: 120, line: 276 }, alignment: AlignmentType.JUSTIFIED, children: parseRuns(t), ...opts });
const bullet = (t) => new Paragraph({ numbering: { reference: "bl", level: 0 }, spacing: { after: 60 }, children: parseRuns(t) });
const num = (t) => new Paragraph({ numbering: { reference: "nl", level: 0 }, spacing: { after: 60 }, children: parseRuns(t) });
const small = (t) => new Paragraph({ spacing: { after: 100 }, children: [new TextRun({ text: t, italics: true, color: GREY, size: 18 })] });

function parseRuns(t) {
  return t.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map((p) =>
    p.startsWith("**") ? new TextRun({ text: p.slice(2, -2), bold: true }) : new TextRun({ text: p }));
}
function cell(text, { bold = false, w, fill } = {}) {
  return new TableCell({
    width: w ? { size: w, type: WidthType.DXA } : undefined,
    shading: fill ? { type: ShadingType.CLEAR, fill } : undefined,
    margins: { top: 60, bottom: 60, left: 90, right: 90 },
    children: [new Paragraph({ children: [new TextRun({ text: String(text), bold, color: bold ? "ffffff" : "000000", size: 19 })] })],
  });
}
function table(headers, rows, widths) {
  const b = { style: BorderStyle.SINGLE, size: 2, color: "c9d3dd" };
  return new Table({
    width: { size: CW, type: WidthType.DXA }, columnWidths: widths,
    borders: { top: b, bottom: b, left: b, right: b, insideHorizontal: b, insideVertical: b },
    rows: [
      new TableRow({ tableHeader: true, children: headers.map((h, i) => cell(h, { bold: true, w: widths[i], fill: NAVY })) }),
      ...rows.map((r, ri) => new TableRow({ children: r.map((c, i) => cell(c, { w: widths[i], fill: ri % 2 ? "eef3f8" : "ffffff" })) })),
    ],
  });
}

const children = [];

// Title
children.push(
  new Paragraph({ spacing: { before: 2400 }, alignment: AlignmentType.CENTER, children: [new TextRun({ text: "▚ TriageDesk", bold: true, size: 54, color: ACCENT })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 160 }, children: [new TextRun({ text: "SOC Alert Triage & Incident Management Platform", bold: true, size: 32, color: NAVY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 500 }, children: [new TextRun({ text: "IT Project 1 — Capstone Report", size: 24, italics: true, color: GREY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80 }, children: [new TextRun({ text: "Approach 1 — Practical IT Project (Build a Working System)", size: 20, color: GREY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 1400 }, children: [new TextRun({ text: "Author: Win Myat Aung (Zane)", size: 22 })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60 }, children: [new TextRun({ text: "Bachelor of Information Technology · Siam University, Bangkok", size: 20, color: GREY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 60 }, children: [new TextRun({ text: "Specialization: Blue Team / SOC Analysis", size: 20, color: GREY })] }),
  new Paragraph({ children: [new PageBreak()] }),
);

// TOC
children.push(
  new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun({ text: "Table of Contents", bold: true, color: NAVY })] }),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
  new Paragraph({ children: [new PageBreak()] }),
);

// Executive summary
children.push(H1("Executive Summary"));
children.push(P("**TriageDesk** is a working Security Operations Centre (SOC) platform for **alert triage and incident management**, built as a practical IT Project 1 capstone. It automates the daily workflow of a tier-1/2 SOC analyst: it ingests security alerts from multiple tools, normalizes them into one schema, enriches them with threat intelligence and business-asset context, correlates related alerts into incidents, tracks service-level-agreement (SLA) deadlines with automatic escalation, and provides a complete analyst workflow — acknowledge, assign, investigate, and resolve with a verdict — on a live web dashboard."));
children.push(P("The project maps directly onto CompTIA CySA+ Domains 1, 3 and 4 (threat management, incident response, and reporting), the author's area of study. It is assessed as a practical build: a demonstrable, tested system rather than a research paper."));
children.push(P("The delivered system comprises roughly 2,400 lines of Python and a single-file web console, backed by **24 automated tests that all pass**. A seeded demonstration dataset immediately populates the dashboard with realistic incidents in varied SLA states, so the platform's metrics — mean time to acknowledge (MTTA), mean time to resolve (MTTR) and SLA compliance — are visible the moment it starts."));

// PHASE 1
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 1 — Identify the Problem"));
children.push(H2("1.1 The problem"));
children.push(P("A modern organisation runs many security tools — endpoint detection, network intrusion detection, firewalls, email gateways — and each produces a stream of alerts in its own format. A SOC analyst is expected to review these alerts, decide which are real, and respond in time. The reality is **alert overload**: analysts face thousands of alerts a day, most of them noise, each in a different format, with no context and no shared workflow. Real threats are missed not because they were invisible, but because they were buried."));
children.push(H2("1.2 Who experiences it and why it matters"));
children.push(bullet("**SOC analysts** burn out triaging high volumes of low-value alerts by hand and switching between tool consoles."));
children.push(bullet("**Organisations** suffer breaches that dwell for weeks because a real alert was lost in the noise or nobody owned it."));
children.push(bullet("**Managers** cannot measure or improve response performance without consistent tracking of who did what, and how fast."));
children.push(H2("1.3 Existing solutions and their limitations"));
children.push(table(
  ["Existing approach", "Limitation"],
  [
    ["Commercial SOAR/SIEM (Splunk, Sentinel, Cortex XSOAR)", "Powerful but expensive, complex, and closed; unsuitable for learning or a small team, and the logic is a black box."],
    ["Reviewing each tool's own console", "No single queue, no correlation across tools, no shared workflow or SLA tracking."],
    ["Spreadsheets / ticket systems", "Manual, no enrichment, no automatic correlation, no security context."],
  ],
  [3400, 5960],
));
children.push(H2("1.4 Proposed solution"));
children.push(P("TriageDesk is a lightweight, open, single-pane platform that takes alerts from any tool, adds the context an analyst needs, groups them into incidents, and manages them through a tracked workflow with SLA deadlines — delivering the core value of a commercial SOAR at a scale a student or small team can build, run and understand."));
children.push(small("Deliverable: Problem Statement + Initial Proposal."));

// PHASE 2
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 2 — Requirements Analysis"));
children.push(H2("2.1 Target users"));
children.push(bullet("**Tier-1/2 SOC analyst** (primary) — triages the queue, investigates and resolves incidents."));
children.push(bullet("**SOC lead** — assigns work, watches SLA compliance and escalations, reviews metrics."));
children.push(bullet("**Security engineer** — integrates new alert sources via the ingestion API."));
children.push(H2("2.2 Functional requirements"));
children.push(table(["ID", "Requirement"], [
  ["FR-1", "Ingest alerts from multiple tools (Wazuh, Suricata, generic/CSV) and via a REST API."],
  ["FR-2", "Normalize every alert into a single common schema regardless of source."],
  ["FR-3", "Enrich alerts with threat-intelligence and asset/business context."],
  ["FR-4", "Compute a risk score combining severity, intel and asset criticality."],
  ["FR-5", "Correlate related alerts from the same actor into a single incident."],
  ["FR-6", "Assign each incident SLA deadlines to acknowledge and to resolve, by severity."],
  ["FR-7", "Detect SLA breaches and automatically escalate overdue, unacknowledged incidents."],
  ["FR-8", "Support the full analyst workflow: acknowledge, assign, investigate, resolve with verdict."],
  ["FR-9", "Record case notes and an immutable audit trail of every action."],
  ["FR-10", "Map incidents to MITRE ATT&CK and provide a response playbook."],
  ["FR-11", "Present a dashboard with the queue, incident detail, and SOC metrics (MTTA/MTTR/compliance)."],
  ["FR-12", "Persist all data so it survives a restart."],
], [1200, 8160]));
children.push(H2("2.3 Non-functional requirements"));
children.push(table(["ID", "Requirement", "Target"], [
  ["NFR-1 Extensibility", "Adding a new alert source must not touch downstream code.", "One parser function per source"],
  ["NFR-2 Portability", "Runs on a student laptop with no external services.", "≤ 8 GB RAM; offline-capable"],
  ["NFR-3 Reproducibility", "Demo state must be identical each run.", "Seeded generator"],
  ["NFR-4 Transparency", "Scoring and correlation must be explainable.", "No black-box models"],
  ["NFR-5 Usability", "An analyst can triage an incident without reading code.", "Playbook + one-click actions"],
  ["NFR-6 Auditability", "Every action must be attributable and recorded.", "Immutable audit log"],
], [2000, 4760, 2600]));
children.push(H2("2.4 Use case — triage an incident (UC-1)"));
children.push(table(["Field", "Detail"], [
  ["Actor", "SOC analyst"],
  ["Precondition", "At least one open incident exists in the queue."],
  ["Main flow", "1. Analyst opens the highest-risk incident. 2. System shows enrichment, ATT&CK mapping, contributing alerts and a playbook. 3. Analyst acknowledges (SLA clock stops), follows the playbook, adds notes. 4. Analyst resolves with a verdict."],
  ["Postcondition", "Incident is resolved with a verdict; MTTA/MTTR and SLA compliance update; the audit trail records each step."],
], [1900, 7460]));
children.push(H2("2.5 User stories"));
children.push(bullet("As an analyst, I want the queue sorted by risk so I work the most dangerous incidents first."));
children.push(bullet("As an analyst, I want threat-intel and asset context on each alert so I can triage in seconds, not minutes."));
children.push(bullet("As a lead, I want overdue incidents escalated automatically so nothing is silently dropped."));
children.push(bullet("As a lead, I want MTTA/MTTR and SLA compliance so I can measure and improve the team."));
children.push(small("Deliverable: Requirements Specification."));

// PHASE 3
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 3 — System Design"));
children.push(H2("3.1 Architecture"));
children.push(P("TriageDesk is a **pipeline**: each stage transforms an alert and passes it on, and the whole flow is driven by one orchestrator that also holds the state the API serves."));
children.push(new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 80, after: 120 }, children: [new TextRun({ text: "Ingest → Normalize → Enrich → Score → Correlate → Apply SLA → Persist → Dashboard", font: "Consolas", size: 18, color: NAVY })] }));
children.push(P("The key architectural decision is **normalize-first**: all source-specific handling happens at ingestion, producing a single `Alert` type. Every later stage — enrichment, scoring, correlation, SLA, UI — operates only on that type, so the system is decoupled from the tools that feed it."));
children.push(H2("3.2 Components"));
children.push(table(["Component", "Responsibility"], [
  ["Normalizer", "Parse Wazuh/Suricata/generic events into the common Alert schema; map severities."],
  ["Enricher", "Add threat-intel, asset context and source direction; offline with optional live providers."],
  ["Risk scorer", "Fuse severity, intel confidence and asset criticality into a 0–100 score."],
  ["Correlator", "Group alerts by acting entity within a time window into incidents."],
  ["SLA engine", "Set deadlines, compute live status, detect breaches, escalate, compute MTTA/MTTR/compliance."],
  ["Workflow", "Enforce status lifecycle; record verdicts, assignments, comments and audit events."],
  ["Database", "SQLite persistence for alerts, incidents, comments, audit and analysts."],
  ["Web/API", "FastAPI backend + single-file analyst dashboard."],
], [2100, 7260]));
children.push(H2("3.3 Data model"));
children.push(P("Five persisted entities. Alerts reference the incident they were correlated into; comments and audit events reference their incident."));
children.push(table(["Entity", "Key fields"], [
  ["Alert", "alert_id, ts, source, rule_id, title, severity, src_ip, dst_ip, user, host, category, technique, risk_score, enrichment, incident_id"],
  ["Incident", "incident_id, created_at, severity, risk_score, status, verdict, assignee, priority, acknowledged_at, resolved_at, ack_due_at, resolve_due_at, ack_breached, escalated, techniques"],
  ["Comment", "comment_id, incident_id, author, text, ts"],
  ["AuditEvent", "audit_id, incident_id, actor, action, detail, ts"],
  ["Analyst", "username, display_name, role"],
], [1700, 7660]));
children.push(H2("3.4 SLA state model"));
children.push(P("Each incident runs two clocks — one to acknowledge, one to resolve — whose deadlines come from the severity policy. A clock is **on track**, **at risk** (inside the final 25% of its window), **breached** (deadline passed) or **met** (milestone reached). A breached acknowledgement clock on an unacknowledged incident triggers **escalation**; acknowledging clears it."));
children.push(H2("3.5 API design (selected)"));
children.push(table(["Endpoint", "Purpose"], [
  ["GET /api/incidents", "Risk-ranked queue with live SLA state (filterable by status/assignee)"],
  ["GET /api/incident/{id}", "Full incident: alerts, enrichment, playbook, comments, audit"],
  ["POST /api/incident/{id}/acknowledge", "Acknowledge (stops the ack clock, assigns to actor)"],
  ["POST /api/incident/{id}/verdict/{v}", "Resolve with a verdict"],
  ["POST /api/ingest", "Ingest a raw alert from an external tool"],
  ["GET /api/metrics", "MTTA, MTTR, SLA compliance, severity mix, counts"],
], [3900, 5460]));
children.push(small("Deliverable: System Design Document."));

// PHASE 4
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 4 — Technology Selection"));
children.push(table(["Choice", "Justification"], [
  ["Python 3.11", "Standard language for security tooling; readable for assessment; socket/sqlite/json in the stdlib kept dependencies tiny."],
  ["FastAPI + Uvicorn", "Minimal, fast, self-documenting REST API; async server handles dashboard polling with a negligible footprint."],
  ["SQLite", "Zero-config, file-based persistence; no database server to run inside the 8 GB budget."],
  ["Single-file HTML/JS dashboard", "No build step or framework; runs offline; the whole UI is one auditable file."],
  ["Bundled JSON threat feed + YAML asset inventory", "Makes enrichment work with no internet and no API keys; swappable for live feeds/CMDB later."],
  ["Optional ip-api.com provider", "Free, no-key geo-enrichment when online, with silent fallback to offline data."],
  ["MITRE ATT&CK", "Industry-standard language for adversary behaviour; makes alerts actionable and the tool résumé-relevant."],
], [2600, 6760]));
children.push(small("Deliverable: Technology Justification."));

// PHASE 5
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 5 — Development"));
children.push(H2("5.1 Methodology"));
children.push(P("Development was **incremental and test-driven**: Design → Develop → Test → Improve. Each stage of the pipeline was built with its own unit tests before the next, so integration was continuous. Git tracked each increment."));
children.push(H2("5.2 Task breakdown"));
children.push(table(["Module", "Key work", "Status"], [
  ["Core", "Data models, SQLite layer, ATT&CK reference", "Complete"],
  ["Ingestion", "Wazuh/Suricata/generic parsers, alert generator", "Complete"],
  ["Enrichment", "Threat-intel + asset matching, optional live provider", "Complete"],
  ["Triage", "Risk scoring, correlation, SLA engine, workflow", "Complete"],
  ["Web", "FastAPI API, analyst dashboard", "Complete"],
  ["Testing", "24 unit + integration tests", "Complete"],
], [1900, 5560, 1900]));
children.push(H2("5.3 Project schedule (15 weeks)"));
children.push(table(["Week", "Activity", "Output"], [
  ["1–3", "Orientation, problem, proposal", "Proposal"],
  ["4", "Requirements", "Requirements spec"],
  ["5", "Technology review", "Tech review"],
  ["6–7", "Methodology + system design", "Design document"],
  ["8", "Midterm presentation", "Progress demo"],
  ["9–10", "Development (pipeline + workflow)", "Prototype"],
  ["11", "Testing", "Test report"],
  ["12", "Improvement (SLA, enrichment, metrics)", "Final build"],
  ["13", "Documentation", "Draft report"],
  ["14–15", "Final presentation + demonstration", "Final project"],
], [1100, 5060, 3200]));
children.push(small("Deliverable: development process, task breakdown, schedule."));

// PHASE 6
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 6 — Testing"));
children.push(P("Testing spans unit, integration and system levels. **All 24 automated tests pass in well under a second**, forming a regression safety net; the seeded demonstration is the system-level test."));
children.push(table(["Test case", "Expected result", "Status"], [
  ["Normalize Wazuh level-12 alert", "Severity mapped to 'critical', fields extracted", "PASS"],
  ["Normalize Suricata EVE alert", "Severity mapped, category preserved", "PASS"],
  ["Source IP on threat feed", "Enrichment adds threat-intel note", "PASS"],
  ["Target is crown-jewel asset", "Asset context added; risk boosted", "PASS"],
  ["Internal source flagged", "Marked as internal (possible compromise)", "PASS"],
  ["5 alerts from one source", "Correlated into a single incident", "PASS"],
  ["Two different sources", "Two separate incidents", "PASS"],
  ["Overdue unacknowledged incident", "SLA breached and escalated", "PASS"],
  ["Acknowledged incident", "Escalation cleared", "PASS"],
  ["Resolve without a verdict", "Rejected (verdict required)", "PASS"],
  ["Resolve with verdict", "Status resolved, resolve time stamped", "PASS"],
  ["MTTA/compliance computation", "Correct averages and percentages", "PASS"],
], [3400, 4360, 1600]));
children.push(small("Deliverable: Test plan and results. Reproduce: python -m pytest tests/ -q"));

// PHASE 7
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 7 — Evaluation"));
children.push(H2("7.1 Against the original objectives"));
children.push(table(["Objective", "Outcome"], [
  ["Did it solve the problem?", "Yes — alerts from multiple tools become one enriched, correlated, risk-ranked queue with a tracked workflow."],
  ["Which requirements were met?", "All 12 functional and 6 non-functional requirements are implemented and tested."],
  ["Does it produce SOC value?", "It computes MTTA, MTTR and SLA compliance and escalates overdue incidents automatically."],
], [3000, 6360]));
children.push(H2("7.2 Demonstration metrics"));
children.push(P("On the seeded dataset (deterministic), the platform produced a realistic operating picture:"));
children.push(table(["Metric", "Value"], [
  ["Alerts ingested / normalized", "66 across 4 source formats"],
  ["Incidents correlated", "42 (from 66 alerts — correlation reduced analyst load)"],
  ["Open incidents / escalated", "21 open, 5 auto-escalated"],
  ["Acknowledgement SLA compliance", "97%"],
  ["Resolution SLA compliance", "81%"],
  ["ATT&CK techniques observed", "6 (of 15 modelled), each with a response playbook"],
  ["Automated tests", "24 passing"],
], [4680, 4680]));
children.push(P("The **correlation** result is worth highlighting: 66 raw alerts collapsed into 42 incidents, and repeated bursts (e.g. brute-force) collapsed many-to-one — exactly the noise reduction the problem statement demanded. The **SLA engine** surfaced 5 escalations that a flat alert list would have hidden."));
children.push(H2("7.3 Limitations"));
children.push(bullet("The **acting-analyst selector** stands in for real authentication; production would use proper login and RBAC."));
children.push(bullet("The **threat feed and asset inventory are bundled samples**, not live feeds or a CMDB."));
children.push(bullet("**Correlation is rule-based** (same actor + time window); statistical or graph-based correlation is future work."));
children.push(small("Deliverable: Evaluation against objectives, with metrics and limitations."));

// PHASE 8
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Phase 8 — Final Demonstration"));
children.push(P("The demonstration shows the **working product**. Suggested flow (~8 minutes):"));
children.push(num("**Problem** (30s): alert overload and lost real threats."));
children.push(num("**Dashboard overview** (1m): the risk-ranked queue, KPI row (open, escalated, MTTA, MTTR, SLA compliance)."));
children.push(num("**Enrichment & risk** (1m): open a high-risk incident; show the threat-feed hit, crown-jewel asset context, and why the risk score is high."));
children.push(num("**Correlation** (1m): show a brute-force incident that grouped many alerts into one case."));
children.push(num("**SLA & escalation** (1m): point to a breached, auto-escalated incident and the countdown chips."));
children.push(num("**Workflow** (2m): acknowledge, follow the ATT&CK playbook, add a note, resolve with a verdict; watch MTTA/compliance update."));
children.push(num("**Integration** (1m): POST a new alert via the API / click Simulate; watch it flow through and appear."));
children.push(num("**Testing** (30s): run the 24-test suite live."));
children.push(H2("Future work (Version 2)"));
children.push(bullet("Real authentication and role-based access control."));
children.push(bullet("Live threat-intel feeds (AbuseIPDB, OTX, MISP) and CMDB asset sync."));
children.push(bullet("Automated response actions (block IP, disable account) — moving from triage toward SOAR."));
children.push(bullet("Forwarding to / ingesting from a SIEM such as Wazuh, which the author already uses."));

// Conclusion + refs
children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("Conclusion"));
children.push(P("TriageDesk delivers a complete, working SOC alert-triage and incident-management platform: multi-source ingestion, contextual enrichment, risk scoring, correlation, SLA tracking with escalation, and a full analyst workflow on a live dashboard — all tested and reproducible on a single laptop. It meets every stated requirement, demonstrates the core value of a commercial SOAR at an understandable scale, and reflects the incident-response skills at the centre of the author's SOC-analyst career path."));
children.push(H1("References"));
[
  "MITRE ATT&CK (Enterprise). https://attack.mitre.org/",
  "CompTIA. CySA+ (CS0-003) Exam Objectives — Domains 1, 3, 4.",
  "Cichonski, P. et al. NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide.",
  "Wazuh Documentation — alert data model. https://documentation.wazuh.com/",
  "Suricata Documentation — EVE JSON output format.",
  "ip-api.com — free IP geolocation API.",
].forEach((r, i) => children.push(new Paragraph({ spacing: { after: 80 }, children: [new TextRun({ text: `[${i + 1}] ${r}`, size: 20 })] })));

const doc = new Document({
  creator: "Win Myat Aung (Zane)", title: "TriageDesk — Capstone Project Report",
  features: { updateFields: true },
  numbering: { config: [
    { reference: "bl", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] },
    { reference: "nl", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] },
  ] },
  styles: { default: { document: { run: { font: "Calibri", size: 22, color: "1a1a1a" } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 30, bold: true, color: NAVY } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 25, bold: true, color: ACCENT } },
    ] },
  sections: [{ properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } }, children }],
});
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync("docs/TriageDesk_Project_Report.docx", buf); console.log("wrote report", buf.length); });
