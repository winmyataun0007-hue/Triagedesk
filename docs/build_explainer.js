// Plain-language talking script to explain TriageDesk to a professor.
const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, HeadingLevel,
  Table, TableRow, TableCell, WidthType, BorderStyle, AlignmentType, ShadingType,
  PageBreak, LevelFormat,
} = require("docx");

const CW = 9360, NAVY = "16263a", ACCENT = "2f6fb0", GREY = "666666";
const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 300, after: 130 }, children: [new TextRun({ text: t, bold: true, color: NAVY })] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 220, after: 90 }, children: [new TextRun({ text: t, bold: true, color: ACCENT })] });
const P = (t) => new Paragraph({ spacing: { after: 120, line: 288 }, children: parseRuns(t) });
const say = (t) => new Paragraph({ spacing: { after: 130, line: 300 }, indent: { left: 340 }, border: { left: { style: BorderStyle.SINGLE, size: 18, color: ACCENT, space: 12 } }, children: [new TextRun({ text: t, italics: true, size: 23, color: "22303c" })] });
const bullet = (t) => new Paragraph({ numbering: { reference: "bl2", level: 0 }, spacing: { after: 70 }, children: parseRuns(t) });
const num = (t) => new Paragraph({ numbering: { reference: "nl2", level: 0 }, spacing: { after: 70 }, children: parseRuns(t) });
function parseRuns(t){return t.split(/(\*\*[^*]+\*\*)/g).filter(Boolean).map(p=>p.startsWith("**")?new TextRun({text:p.slice(2,-2),bold:true}):new TextRun({text:p}));}
function cell(t,{bold=false,w,fill}={}){return new TableCell({width:w?{size:w,type:WidthType.DXA}:undefined,shading:fill?{type:ShadingType.CLEAR,fill}:undefined,margins:{top:60,bottom:60,left:90,right:90},children:[new Paragraph({children:[new TextRun({text:String(t),bold,color:bold?"ffffff":"000000",size:20})]})]});}
function table(headers,rows,widths){const b={style:BorderStyle.SINGLE,size:2,color:"c9d3dd"};return new Table({width:{size:CW,type:WidthType.DXA},columnWidths:widths,borders:{top:b,bottom:b,left:b,right:b,insideHorizontal:b,insideVertical:b},rows:[new TableRow({tableHeader:true,children:headers.map((h,i)=>cell(h,{bold:true,w:widths[i],fill:NAVY}))}),...rows.map((r,ri)=>new TableRow({children:r.map((c,i)=>cell(c,{w:widths[i],fill:ri%2?"eef3f8":"ffffff"}))}))]});}

const children = [];
children.push(
  new Paragraph({ spacing: { before: 200 }, children: [new TextRun({ text: "▚ TriageDesk", bold: true, size: 40, color: ACCENT })] }),
  new Paragraph({ spacing: { before: 60 }, children: [new TextRun({ text: "Explaining My Project — Simple Talking Script", bold: true, size: 30, color: NAVY })] }),
  new Paragraph({ spacing: { before: 40, after: 160 }, children: [new TextRun({ text: "A plain-English guide for presenting to my professor. Text in the blue bar is what I can say out loud.", italics: true, size: 20, color: GREY })] }),
);

children.push(H1("1. The project in one sentence"));
children.push(say("“I built a tool that helps a security analyst handle the flood of security alerts — it collects them from different tools, adds useful context, groups related ones together, and tracks how fast the team responds.”"));

children.push(H1("2. The simple picture (analogy)"));
children.push(P("A company's security tools are like many smoke detectors all over a building — one on the network, one on each computer, one on the email system. Each one beeps in its own way, and there are **thousands of beeps a day**. Most are nothing (someone burned toast); a few are a real fire. One person cannot listen to every detector in every room."));
children.push(say("“TriageDesk is like a single control room for all those alarms. It brings every beep into one screen, labels which room it came from and how dangerous it is, groups beeps that are really the same fire, and starts a timer so nothing important is ignored for too long.”"));

children.push(H1("3. Why this matters"));
children.push(P("This is the real, everyday job of a **SOC analyst** — the role I'm training for. Companies get breached not because the alert never fired, but because it was **lost in the noise** or nobody owned it in time. My tool attacks exactly that problem, and it's built around the same incident-response process I'm studying for my CySA+ certification."));

children.push(H1("4. What I actually built"));
children.push(P("One working system with a clear flow. An alert goes through five steps:"));
children.push(bullet("**Collect & translate** — take alerts from different tools (each speaks a different format) and rewrite them all into one common format."));
children.push(bullet("**Add context (enrich)** — automatically answer: is this attacker's address on a known-bad list? Is the target one of our important systems? Is the source inside our own network?"));
children.push(bullet("**Score the risk** — combine all of that into one 0–100 number so the analyst knows what to look at first."));
children.push(bullet("**Group (correlate)** — put alerts that are really the same attack into one 'incident', so the analyst sees one case instead of fifty beeps."));
children.push(bullet("**Track the clock (SLA)** — give each incident a deadline based on how serious it is, warn when time is running out, and automatically raise an alarm if a serious one is ignored too long."));
children.push(P("On top of that sits the **analyst workflow**: pick up an incident, follow a built-in checklist, write notes, and close it with a decision (real threat / false alarm). Every action is recorded."));

children.push(H1("5. The one feature that makes it special"));
children.push(P("Anyone can build a list of alerts. What makes this a real **incident-management** tool is the **SLA clock and automatic escalation**: it measures how fast the team acknowledges and resolves incidents, flags the ones that break their deadline, and pushes overdue serious ones to the top. That's what lets a manager measure the team with numbers like **MTTA** (average time to acknowledge) and **MTTR** (average time to resolve)."));

children.push(H1("6. What I can show working"));
children.push(P("When the dashboard opens, it already has realistic data. I can show:"));
children.push(bullet("**66 alerts** from 4 different tool formats, automatically turned into **42 grouped incidents** — that grouping is the noise reduction."));
children.push(bullet("A risk-ranked queue, with the most dangerous incidents (and any **escalated** ones) at the top."));
children.push(bullet("Live team metrics: MTTA, MTTR, and **SLA compliance** (e.g. 97% of alerts acknowledged on time)."));
children.push(bullet("**24 automated tests** that all pass, proving each part works."));

children.push(H1("7. What it cannot do yet (being honest)"));
children.push(bullet("It uses a simple 'who am I' dropdown instead of a real login system — that's the next step."));
children.push(bullet("The threat-intelligence list and the list of important systems are built-in samples, not live feeds (though it's designed so real feeds can be plugged in)."));
children.push(bullet("It helps the analyst respond, but doesn't yet take actions automatically (like blocking an attacker) — that would move it toward a full 'SOAR' platform."));

children.push(new Paragraph({ children: [new PageBreak()] }));
children.push(H1("8. The live demo (what I will click and say)"));
children.push(table(["I click / show", "I say"], [
  ["The dashboard KPI row.", "“Here's the whole SOC at a glance — open incidents, escalations, and how fast we respond.”"],
  ["The queue, sorted by risk.", "“The most dangerous incidents are at the top; the red 'ESC' tags are ones the system escalated because they were ignored too long.”"],
  ["Open a high-risk incident.", "“The system already told me the source is on a threat feed and the target is our payroll database — that's why it's high risk.”"],
  ["Point at the grouped alerts.", "“This one incident is actually several alerts the system grouped together, so I work one case, not five.”"],
  ["Point at the SLA chips + playbook.", "“There's a countdown to my deadline, and a built-in checklist of response steps.”"],
  ["Acknowledge, then resolve with a verdict.", "“I take ownership, follow the steps, and close it as a real threat — and the team's response-time metrics update.”"],
  ["Click 'Simulate alerts'.", "“New alerts flow in live and get processed automatically.”"],
], [3400, 5960]));

children.push(H1("9. Questions my professor might ask (and simple answers)"));
children.push(table(["Question", "My short answer"], [
  ["Isn't this just a to-do list?", "No — it enriches, correlates and risk-scores automatically, and tracks SLAs with escalation. A to-do list does none of that."],
  ["Why not use Splunk/Sentinel?", "Those are powerful but expensive black boxes. I built an open, understandable version so I learn how it actually works — which is the point of the project."],
  ["How do you handle different tools?", "Every alert is translated into one common format at the entrance, so the rest of the system doesn't care which tool it came from. Adding a tool is one small function."],
  ["How do you know it works?", "24 automated tests cover parsing, enrichment, correlation, SLA breaches and the workflow, and they all pass. The demo data is reproducible."],
  ["What's the hardest part?", "The SLA engine — getting the deadlines, breach detection and escalation correct for both live and historical incidents."],
], [3200, 6160]));

children.push(H1("10. If I only have 20 seconds"));
children.push(say("“Security teams drown in thousands of alerts a day and miss the real ones. I built a control room that pulls every alert into one place, adds context automatically, groups related alerts into incidents, and tracks response deadlines so nothing serious gets ignored. It turns 66 raw alerts into 42 managed incidents and measures how fast the team responds — the core job of a SOC analyst, in one tool.”"));

const doc = new Document({
  creator: "Win Myat Aung (Zane)", title: "TriageDesk — Simple Explainer Script",
  numbering: { config: [
    { reference: "bl2", levels: [{ level: 0, format: LevelFormat.BULLET, text: "•", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] },
    { reference: "nl2", levels: [{ level: 0, format: LevelFormat.DECIMAL, text: "%1.", alignment: AlignmentType.LEFT, style: { paragraph: { indent: { left: 460, hanging: 260 } } } }] },
  ] },
  styles: { default: { document: { run: { font: "Calibri", size: 23, color: "1a1a1a" } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 30, bold: true, color: NAVY } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true, run: { size: 24, bold: true, color: ACCENT } },
    ] },
  sections: [{ properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } }, children }],
});
Packer.toBuffer(doc).then((buf) => { fs.writeFileSync("docs/TriageDesk_Explainer_Script.docx", buf); console.log("wrote explainer", buf.length); });
