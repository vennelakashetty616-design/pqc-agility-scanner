from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pqcscan.analysis import ScanRequestError, analyze_directory
from pqcscan.chat import answer_question
from pqcscan.disclaimer import DISCLAIMER
from pqcscan.sandbox.provider import ClassicalProvider, UnsupportedProfile, list_profiles

_SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "legacy-billing"

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Crypto practice dashboard</title>
<style>
  :root {
    color-scheme: light;
    --ink: #102a43;
    --muted: #52606d;
    --line: #e4e7eb;
    --paper: #eef3f8;
    --card: #ffffff;
    --urgent: #e11d48;
    --plan: #ea580c;
    --keep: #059669;
    --lib: #2563eb;
    --uncertain: #7c3aed;
    --navy: #102a43;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font: 16px/1.5 "Segoe UI", system-ui, sans-serif;
    color: var(--ink);
    background: var(--paper);
  }
  button, input { font: inherit; }
  .wrap { width: min(1140px, calc(100% - 28px)); margin: 0 auto; }
  .top { background: var(--navy); color: #f8fafc; padding: 28px 0 22px; }
  .kicker { margin: 0 0 6px; letter-spacing: 0.12em; text-transform: uppercase; font-size: 12px; color: #7dd3fc; font-weight: 700; }
  h1 { font-size: 36px; line-height: 1.1; margin: 0 0 8px; font-weight: 750; }
  h2 { font-size: 20px; margin: 0 0 6px; }
  h3 { font-size: 16px; margin: 0; }
  p { margin: 0 0 8px; }
  .lede { color: #d9e2ec; max-width: 70ch; }
  form {
    display: grid;
    grid-template-columns: 1fr auto auto;
    gap: 8px;
    align-items: end;
    margin-top: 16px;
    padding: 12px;
    background: #fff;
    color: var(--ink);
    border-radius: 16px;
  }
  label { display: block; font-size: 12px; font-weight: 700; color: var(--muted); margin-bottom: 4px; }
  input[type="text"], #q {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--line);
    border-radius: 10px;
    background: #f8fafc;
    color: var(--ink);
  }
  #path { font-family: Consolas, ui-monospace, monospace; font-size: 14px; }
  button { border: 0; cursor: pointer; border-radius: 10px; }
  button.primary { background: var(--urgent); color: white; padding: 11px 16px; font-weight: 700; }
  button.quiet { background: #fff7ed; color: #9a3412; padding: 11px 14px; font-weight: 700; }
  button:disabled { opacity: 0.55; cursor: wait; }
  #status { min-height: 1.4em; color: #d9e2ec; margin: 10px 0 0; }
  #status.error { color: #fecdd3; }
  #dashboard { padding: 18px 0 48px; }
  .note {
    background: #fffbeb;
    border: 1px solid #fcd34d;
    border-radius: 14px;
    padding: 12px 14px;
    margin-bottom: 14px;
  }
  .headline { font-size: 28px; line-height: 1.2; margin: 0 0 8px; }
  .meta { color: var(--muted); font-size: 14px; }
  code { font-family: Consolas, ui-monospace, monospace; font-size: 0.92em; }
  .legend { display: flex; flex-wrap: wrap; gap: 8px; margin: 12px 0; }
  .legend span, .pill {
    display: inline-flex; align-items: center; gap: 6px;
    background: white; border-radius: 999px; padding: 4px 10px; font-size: 13px; font-weight: 650;
  }
  .dot { width: 10px; height: 10px; border-radius: 99px; display: inline-block; }
  .dot.urgent, .pill.urgent { background: var(--urgent); }
  .pill.urgent, .pill.plan, .pill.monitor, .pill.informational, .pill.uncertain { color: white; }
  .dot.plan, .pill.plan { background: var(--plan); }
  .dot.monitor, .pill.monitor { background: var(--keep); }
  .dot.informational, .pill.informational { background: var(--lib); }
  .dot.uncertain, .pill.uncertain { background: var(--uncertain); }
  .stats { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin: 8px 0 14px; }
  .stat {
    text-align: left; color: white; border-radius: 16px; padding: 14px 14px 16px; min-height: 108px;
    box-shadow: 0 10px 24px rgba(16, 42, 67, 0.12);
  }
  .stat b { display: block; font-size: 36px; line-height: 1; }
  .stat small { display: block; margin-top: 8px; opacity: 0.95; }
  .stat.urgent { background: var(--urgent); }
  .stat.plan { background: var(--plan); }
  .stat.keep { background: var(--keep); }
  .stat.uncertain { background: var(--uncertain); }
  .stat.on { outline: 3px solid var(--navy); outline-offset: 3px; }
  .tabs { display: flex; flex-wrap: wrap; gap: 8px; margin: 6px 0 14px; }
  .tabs button { background: white; color: var(--ink); border: 1px solid var(--line); padding: 8px 14px; border-radius: 999px; font-weight: 700; }
  .tabs button.active { background: var(--navy); color: white; }
  .card { background: var(--card); border-radius: 16px; padding: 16px; box-shadow: 0 8px 20px rgba(16, 42, 67, 0.05); }
  .grid { display: grid; grid-template-columns: 0.9fr 1.1fr; gap: 14px; }
  .split { display: grid; grid-template-columns: 180px 1fr; gap: 12px; align-items: center; }
  .donut { width: 180px; height: 180px; }
  .mix { display: flex; height: 22px; border-radius: 999px; overflow: hidden; background: #e5e7eb; margin-top: 8px; }
  .mix button { border-radius: 0; color: white; font-size: 12px; font-weight: 800; min-width: 0; padding: 0; }
  .mix .urgent { background: var(--urgent); }
  .mix .plan { background: var(--plan); }
  .mix .monitor { background: var(--keep); }
  .mix .informational { background: var(--lib); }
  .bar-row { display: grid; grid-template-columns: minmax(110px, 180px) 1fr 36px; gap: 8px; align-items: center; margin: 8px 0; }
  .bar-label { font-size: 14px; font-weight: 650; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .bar-track { height: 14px; background: #eef2f7; border-radius: 99px; overflow: hidden; }
  .bar-fill { height: 14px; border-radius: 99px; width: 0; transition: width 0.45s ease; }
  .lanes { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 14px; }
  .lane { border-radius: 16px; padding: 14px; background: white; }
  .lane header { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
  .lane header b { margin-left: auto; }
  .lane.urgent { background: #fff1f2; }
  .lane.plan { background: #fff7ed; }
  .lane.monitor { background: #ecfdf5; }
  .lane.informational { background: #eff6ff; }
  .tiles { display: flex; flex-wrap: wrap; gap: 8px; }
  .tile {
    text-align: left; background: white; border-radius: 12px; padding: 8px 10px; border: 2px solid transparent;
    box-shadow: 0 1px 0 rgba(16, 42, 67, 0.04);
  }
  .tile strong { display: block; }
  .tile span { color: var(--muted); font-size: 12px; }
  .tile.on { border-color: var(--navy); }
  #detail { margin-top: 12px; border-radius: 16px; padding: 16px 16px 8px; background: white; border-left: 8px solid var(--navy); }
  #detail.urgent { border-color: var(--urgent); background: #fff1f2; }
  #detail.plan { border-color: var(--plan); background: #fff7ed; }
  #detail.monitor { border-color: var(--keep); background: #ecfdf5; }
  #detail.informational { border-color: var(--lib); background: #eff6ff; }
  .where { font-family: Consolas, ui-monospace, monospace; font-size: 13px; color: var(--muted); }
  .code-hit { margin: 8px 0 0; background: #102a43; color: #f8fafc; border-radius: 10px; padding: 8px 10px; overflow: auto; }
  .code-hit .file { display: block; color: #7dd3fc; font-size: 12px; margin-bottom: 4px; }
  .code-hit code { color: #f8fafc; white-space: pre-wrap; font-family: Consolas, ui-monospace, monospace; font-size: 13px; }
  .timeline { list-style: none; margin: 0; padding: 0; }
  .timeline li { display: grid; grid-template-columns: 36px 1fr; gap: 10px; margin: 0 0 10px; }
  .num { width: 36px; height: 36px; border-radius: 12px; color: white; display: grid; place-items: center; font-weight: 800; }
  .num.urgent { background: var(--urgent); }
  .num.plan { background: var(--plan); }
  .step { background: white; border-radius: 14px; padding: 10px 12px; }
  .pair { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-top: 14px; }
  .flow { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; }
  .flow .from, .flow .to { background: white; border-radius: 12px; padding: 8px 10px; }
  .arrow { color: var(--plan); font-weight: 800; }
  .tools { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-bottom: 12px; }
  .chip { background: white; border: 1px solid var(--line); padding: 7px 12px; border-radius: 999px; font-weight: 700; }
  .chip.on { color: white; }
  .chip.on.all { background: var(--navy); }
  .chip.on.urgent { background: var(--urgent); }
  .chip.on.plan { background: var(--plan); }
  .chip.on.monitor { background: var(--keep); }
  .chip.on.uncertain { background: var(--uncertain); }
  #q { max-width: 280px; }
  .hits { display: grid; gap: 8px; }
  .hit { background: white; border-radius: 14px; padding: 10px 12px; border-left: 6px solid var(--lib); }
  .hit.urgent { border-color: var(--urgent); }
  .hit.plan { border-color: var(--plan); }
  .hit.monitor { border-color: var(--keep); }
  .hit.uncertain { border-color: var(--uncertain); }
  .hit-top { display: flex; justify-content: space-between; gap: 8px; align-items: center; }
  .muted { color: var(--muted); }
  details summary { cursor: pointer; font-weight: 700; }
  @media (max-width: 860px) {
    h1 { font-size: 28px; }
    form, .stats, .grid, .lanes, .pair, .split, .bar-row { grid-template-columns: 1fr; }
    .donut { margin: 0 auto; }
    #chat { width: calc(100% - 20px); right: 10px; }
  }
  #ask-open {
    position: fixed; right: 18px; bottom: 18px; z-index: 30;
    background: var(--navy); color: white; padding: 12px 18px; border-radius: 999px;
    font-weight: 800; box-shadow: 0 12px 28px rgba(16, 42, 67, 0.28);
  }
  #chat[hidden] { display: none; }
  #chat {
    position: fixed; right: 18px; bottom: 72px; z-index: 30;
    width: min(400px, calc(100% - 24px)); height: min(560px, calc(100% - 96px));
    background: white; border-radius: 18px; box-shadow: 0 18px 50px rgba(16, 42, 67, 0.22);
    display: flex; flex-direction: column; overflow: hidden;
  }
  #chat header { flex: 0 0 auto; display: flex; justify-content: space-between; align-items: flex-start; gap: 8px; background: var(--navy); color: white; padding: 12px 14px; }
  #chat header p { margin: 2px 0 0; color: #d9e2ec; font-size: 13px; }
  #ask-close { background: transparent; color: white; font-weight: 700; flex: 0 0 auto; }
  #chat-log { flex: 1; overflow: auto; padding: 12px; display: flex; flex-direction: column; gap: 8px; background: #f8fafc; }
  .suggest { flex: 0 0 auto; display: flex; flex-wrap: wrap; gap: 6px; padding: 0 12px 8px; background: #f8fafc; }
  #ask-form { flex: 0 0 auto; display: grid; grid-template-columns: 1fr auto; gap: 8px; padding: 10px; border-top: 1px solid var(--line); }
  .bubble { max-width: 92%; padding: 8px 10px; border-radius: 12px; white-space: pre-wrap; }
  .bubble.user { align-self: flex-end; background: var(--navy); color: white; }
  .bubble.bot { align-self: flex-start; background: white; border-left: 4px solid var(--plan); }
  .suggest button { background: #fff7ed; color: #9a3412; border-radius: 999px; padding: 6px 10px; font-size: 13px; font-weight: 700; }
  #ask-input { border: 1px solid var(--line); border-radius: 10px; padding: 10px; }
  #ask-form button { background: var(--urgent); color: white; font-weight: 800; padding: 0 14px; }
</style>
</head>
<body>
<div class="top">
  <div class="wrap">
    <p class="kicker">Crypto practice dashboard</p>
    <h1>What cryptography this code is using</h1>
    <p class="lede">Scan any project folder. The colors are the whole story: red means retire it, orange means plan it, green means keep it, blue means it is only a library or a name. Click a color or a practice to read that part. The wording comes from the scan rules. It is not a live model, and it does not prove a system is quantum-safe.</p>
    <form id="scan-form">
      <div>
        <label for="path">Folder to scan</label>
        <input id="path" name="path" type="text" spellcheck="false" value="__DEFAULT_PATH__">
      </div>
      <button class="primary" id="scan-btn" type="submit">Scan folder</button>
      <button class="quiet" id="sample-btn" type="button">Use sample</button>
    </form>
    <p id="status">Choose a folder and scan it.</p>
  </div>
</div>
<main id="dashboard" class="wrap" hidden>
  <div class="note"><b>Read this first.</b> <span id="disclaimer"></span></div>
  <h2 class="headline" id="headline"></h2>
  <p class="meta">Scanned <code id="root"></code> · <span id="file-count"></span> · <span id="skip-count"></span> skipped</p>
  <div class="legend">
    <span><i class="dot urgent"></i> Retire now</span>
    <span><i class="dot plan"></i> Plan a migration</span>
    <span><i class="dot monitor"></i> Keep, with an owner</span>
    <span><i class="dot informational"></i> Library or name only</span>
    <span><i class="dot uncertain"></i> Comment, not confirmed</span>
  </div>
  <div id="mix" class="mix"></div>
  <section class="stats" id="stats"></section>
  <nav class="tabs">
    <button type="button" class="active" data-tab="picture">Picture</button>
    <button type="button" data-tab="update">What to update</button>
    <button type="button" data-tab="evidence">Evidence</button>
  </nav>
  <section id="tab-picture">
    <div class="grid">
      <div class="card">
        <h2>How the confirmed hits split</h2>
        <p class="muted">These are the same numbers as the colored buttons. Click one.</p>
        <div class="split">
          <div id="donut"></div>
          <div id="concern-chart"></div>
        </div>
      </div>
      <div class="card">
        <h2>What kind of cryptography</h2>
        <p class="muted">This is the job the code asks cryptography to do. It is not a safety score.</p>
        <div id="usage-chart"></div>
      </div>
    </div>
    <div class="card" style="margin-top:14px">
      <h2>Files with the most confirmed hits</h2>
      <div id="file-chart"></div>
    </div>
    <div id="lanes" class="lanes"></div>
    <section id="detail" hidden>
      <div class="hit-top"><h2 id="detail-name"></h2><span id="detail-pill" class="pill"></span></div>
      <p id="detail-plain"></p>
      <p id="detail-action"></p>
      <div id="detail-lines"></div>
    </section>
    <p class="muted" style="margin-top:12px"><button type="button" id="more-reading" class="chip">Read the full explanation</button></p>
    <p id="narrative" hidden></p>
  </section>
  <section id="tab-update" hidden>
    <h2>What to update, against published guidance</h2>
    <p class="muted">Do the red steps first. Orange steps are a plan, not an emergency. Passing a step is not a quantum-safety result.</p>
    <div id="updates"></div>
    <div class="pair">
      <div class="card">
        <h2>Easy to miss</h2>
        <p class="muted">These files never name the algorithm. They call a file that does.</p>
        <div id="hidden" class="flow"></div>
      </div>
      <div class="card">
        <h2>What can break if you change it</h2>
        <ol id="risks"></ol>
        <h3 style="margin-top:14px">How to check a change</h3>
        <ol id="checks"></ol>
      </div>
    </div>
  </section>
  <section id="tab-evidence" hidden>
    <h2>File and line</h2>
    <p class="muted">Each card is one place in the folder. The dark box is the file, the line number, and the line of code the scanner matched.</p>
    <div class="tools">
      <div id="filters"></div>
      <input id="q" type="text" placeholder="Search a name or file">
    </div>
    <div id="findings" class="hits"></div>
    <p class="muted" id="truncated" hidden>The list stops at 400 rows. The JSON report has the rest.</p>
  </section>
  <details class="card" style="margin-top:14px">
    <summary>What this scan cannot see</summary>
    <ul id="limits"></ul>
  </details>
  <p class="muted" style="margin-top:14px">A clean view is not a quantum-safety attestation.</p>
</main>
<button id="ask-open" type="button">Ask</button>
<section id="chat" hidden>
  <header>
    <div>
      <strong>Ask about this scan</strong>
      <p>Answers come from the findings on this page. This is not a live model, and it does not decide that a system is quantum-safe.</p>
    </div>
    <button id="ask-close" type="button">Close</button>
  </header>
  <div id="chat-log"></div>
  <div class="suggest">
    <button type="button" data-ask="What should we fix first?">What to fix first</button>
    <button type="button" data-ask="What do the colors mean?">Colors</button>
    <button type="button" data-ask="Does this prove we are quantum-safe?">Quantum-safe? It does not</button>
    <button type="button" data-ask="Where is MD5?">MD5</button>
  </div>
  <form id="ask-form">
    <input id="ask-input" type="text" placeholder="Ask about a color, a file, or a practice" maxlength="500">
    <button type="submit">Send</button>
  </form>
</section>
<script>
const SAMPLE = __SAMPLE_JSON__;
const input = document.getElementById("path");
const status = document.getElementById("status");
const dashboard = document.getElementById("dashboard");
const scanBtn = document.getElementById("scan-btn");
const HUES = ["#e11d48", "#ea580c", "#d97706", "#059669", "#0891b2", "#2563eb", "#4f46e5", "#7c3aed", "#db2777", "#0f766e", "#475569"];
const TONE = { urgent: "Retire now", plan: "Plan a migration", monitor: "Keep, with an owner", informational: "Library or name only", uncertain: "Comment only" };
let current = null;
let filter = "all";
let query = "";

function esc(value) {
  return String(value).replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[ch]));
}
function codeBlock(where, snippet) {
  if (!snippet) return where ? `<p class="where">${esc(where)}</p>` : "";
  return `<pre class="code-hit"><span class="file">${esc(where || "line")}</span><code>${esc(snippet)}</code></pre>`;
}
function shortPath(path) {
  const parts = String(path).split(/[/\\\\]/).filter(Boolean);
  return parts.slice(-2).join("/");
}
function paintBars(target, series, colorOf) {
  const max = Math.max(1, ...series.map((item) => item.count));
  if (!series.length) {
    target.innerHTML = "<p class='muted'>Nothing confirmed in this chart.</p>";
    return;
  }
  target.innerHTML = series.map((item, index) => `
    <button type="button" class="bar-row" data-filter="${esc(item.key || "")}" style="background:transparent;padding:0;text-align:left;width:100%">
      <div class="bar-label" title="${esc(item.label)}">${esc(shortPath(item.label))}</div>
      <div class="bar-track"><div class="bar-fill" style="width:${Math.max(6, item.count / max * 100)}%;background:${colorOf(item, index)}"></div></div>
      <div>${item.count}</div>
    </button>
  `).join("");
}
function donut(series) {
  const colors = { urgent: "#e11d48", plan: "#ea580c", monitor: "#059669", informational: "#2563eb" };
  const total = series.reduce((sum, item) => sum + item.count, 0);
  if (!total) {
    document.getElementById("donut").innerHTML = "<p class='muted'>Nothing confirmed in this chart.</p>";
    return;
  }
  const radius = 52;
  const circ = 2 * Math.PI * radius;
  let offset = 0;
  const rings = series.map((item) => {
    const len = item.count / total * circ;
    const gap = len > 8 ? 3 : 0;
    const dash = Math.max(len - gap, 1);
    const ring = `<circle cx="70" cy="70" r="${radius}" fill="none" stroke="${colors[item.key] || "#64748b"}" stroke-width="16" stroke-dasharray="${dash} ${circ - dash}" stroke-dashoffset="${-offset}" transform="rotate(-90 70 70)"></circle>`;
    offset += len;
    return ring;
  }).join("");
  document.getElementById("donut").innerHTML = `<svg class="donut" viewBox="0 0 140 140" role="img" aria-label="How the confirmed hits split">${rings}<text x="70" y="66" text-anchor="middle" font-size="28" font-weight="700" fill="#102a43">${total}</text><text x="70" y="86" text-anchor="middle" font-size="11" fill="#52606d">practices</text></svg>`;
}
function matches(item) {
  if (filter === "uncertain") return item.confidence !== "confirmed";
  if (filter !== "all" && !(item.concern === filter && item.confidence === "confirmed")) return false;
  if (!query) return true;
  return (item.name + " " + item.where + " " + item.plain).toLowerCase().includes(query);
}
function paint() {
  const data = current;
  const counts = data.counts;
  document.getElementById("stats").innerHTML = [
    ["urgent", counts.retire, "Click to see what to retire"],
    ["plan", counts.plan, "Click to see what to plan"],
    ["keep", counts.keep, "Click to see what to keep"],
    ["uncertain", counts.uncertain, "Click to see comments only"]
  ].map(([key, value, label]) => `<button type="button" class="stat ${key} ${filter === key ? "on" : ""}" data-filter="${key}"><b>${value}</b><small>${label}</small></button>`).join("");
  const practiceSeries = [
    { key: "urgent", label: "Retire now", count: counts.retire },
    { key: "plan", label: "Plan a migration", count: counts.plan },
    { key: "monitor", label: "Keep, with an owner", count: counts.keep },
    { key: "informational", label: "Library or name only", count: counts.libraries }
  ].filter((item) => item.count);
  const practiceTotal = practiceSeries.reduce((sum, item) => sum + item.count, 0) || 1;
  document.getElementById("mix").innerHTML = practiceSeries.map((item) => {
    const width = item.count / practiceTotal * 100;
    const label = width > 12 ? String(item.count) : "";
    return `<button type="button" class="${item.key}" data-filter="${item.key}" style="width:${width}%" title="${esc(item.label)}: ${item.count}">${label}</button>`;
  }).join("");
  donut(practiceSeries);
  paintBars(document.getElementById("concern-chart"), practiceSeries, (item) => ({ urgent: "#e11d48", plan: "#ea580c", monitor: "#059669", informational: "#2563eb" }[item.key] || "#64748b"));
  paintBars(document.getElementById("usage-chart"), data.charts.usage, (_item, index) => HUES[index % HUES.length]);
  paintBars(document.getElementById("file-chart"), data.charts.files, (_item, index) => HUES[index % HUES.length]);
  const notes = data.findings.filter((item) => item.confidence !== "confirmed");
  if (filter === "uncertain") {
    document.getElementById("lanes").innerHTML = `<section class="lane" style="background:#f5f3ff"><header><i class="dot uncertain"></i><h3>Comments, not confirmed use</h3><b>${notes.length}</b></header><p class="muted">Do not schedule a migration from a comment.</p><div class="hits">${notes.map((item) => `<article class="hit uncertain"><strong>${esc(item.name)}</strong><p>${esc(item.plain)}</p>${codeBlock(item.where, item.snippet)}</article>`).join("") || "<p class='muted'>None in this folder.</p>"}</div></section>`;
  } else {
  const lanes = data.standards.filter((group) => filter === "all" || group.key === filter);
  document.getElementById("lanes").innerHTML = lanes.map((group) => `
    <section class="lane ${group.key}">
      <header><i class="dot ${group.key}"></i><h3>${esc(group.title)}</h3><b>${group.items.length}</b></header>
      <p class="muted">${esc(group.guidance)}</p>
      <div class="tiles">
        ${group.items.length ? group.items.map((item, index) => `
          <button type="button" class="tile" data-tile="${group.key}:${index}">
            <strong>${esc(item.name)}</strong>
            <span>${item.count} hit${item.count === 1 ? "" : "s"}</span>
          </button>
        `).join("") : "<p class='muted'>None confirmed.</p>"}
      </div>
    </section>
  `).join("") || "<p class='muted'>Nothing in this color.</p>";
  }
  document.getElementById("updates").innerHTML = data.updates.length ? `<ol class="timeline">${data.updates.filter((item) => filter === "all" || item.concern === filter).map((item) => `
    <li>
      <div class="num ${item.concern}">${item.priority}</div>
      <div class="step">
        <strong>${esc(item.title)}</strong>
        <p>${esc(item.action)}</p>
        ${codeBlock(item.where, item.snippet)}
        <p class="muted">${esc(item.gate)}</p>
      </div>
    </li>
  `).join("")}</ol>` : "<p class='muted'>No confirmed retire-or-plan item in this folder.</p>";
  document.getElementById("hidden").innerHTML = data.hidden.length ? data.hidden.map((item) => `
    <div class="from"><strong>${esc(item.mechanism)}</strong><div class="where">${esc(shortPath(item.caller))}</div></div>
    <span class="arrow">calls</span>
    <div class="to where">${esc(shortPath(item.origin))}</div>
  `).join("") : "<p class='muted'>No wrapper-only use was found.</p>";
  const filters = [["all", "All"], ["urgent", "Retire"], ["plan", "Plan"], ["monitor", "Keep"], ["uncertain", "Uncertain"]];
  document.getElementById("filters").innerHTML = filters.map(([key, label]) =>
    `<button type="button" class="chip ${filter === key ? "on " + key : ""}" data-filter="${key}">${label}</button>`
  ).join("");
  const rows = data.findings.filter(matches).slice(0, 80);
  document.getElementById("findings").innerHTML = rows.map((item) => {
    const tone = item.confidence === "confirmed" ? item.concern : "uncertain";
    return `<article class="hit ${tone}"><div class="hit-top"><strong>${esc(item.name)}</strong><span class="pill ${tone}">${esc(TONE[tone] || tone)}</span></div><p>${esc(item.plain)}</p>${codeBlock(item.where, item.snippet)}</article>`;
  }).join("") || "<p class='muted'>Nothing in this filter.</p>";
}
function openTile(token) {
  const [key, indexText] = token.split(":");
  const group = current.standards.find((item) => item.key === key);
  const item = group && group.items[Number(indexText)];
  if (!item) return;
  const box = document.getElementById("detail");
  const update = current.updates.find((row) => row.title === item.name);
  box.hidden = false;
  box.className = key;
  document.getElementById("detail-name").textContent = item.name;
  const pill = document.getElementById("detail-pill");
  pill.textContent = TONE[key] || key;
  pill.className = "pill " + key;
  document.getElementById("detail-plain").textContent = item.plain;
  document.getElementById("detail-action").textContent = update ? update.action : "";
  const spots = item.locations || [];
  document.getElementById("detail-lines").innerHTML = spots.length
    ? spots.map((spot) => codeBlock(spot.line ? spot.path + ":" + spot.line : spot.path, spot.snippet)).join("")
    : "";
  box.scrollIntoView({ behavior: "smooth", block: "nearest" });
}
function render(data) {
  current = data;
  filter = "all";
  query = "";
  document.getElementById("q").value = "";
  dashboard.hidden = false;
  document.getElementById("disclaimer").textContent = data.disclaimer;
  document.getElementById("headline").textContent = data.headline;
  document.getElementById("narrative").textContent = data.narrative;
  document.getElementById("narrative").hidden = true;
  document.getElementById("root").textContent = data.root;
  const fileWord = data.files_scanned === 1 ? "file" : "files";
  document.getElementById("file-count").textContent = data.files_scanned + " " + fileWord;
  document.getElementById("skip-count").textContent = String(data.files_skipped);
  document.getElementById("risks").innerHTML = data.risks.map((item) => `<li>${esc(item)}</li>`).join("");
  document.getElementById("checks").innerHTML = data.checks.map((item) => `<li>${esc(item)}</li>`).join("");
  document.getElementById("limits").innerHTML = data.limitations.map((item) => `<li>${esc(item)}</li>`).join("");
  document.getElementById("truncated").hidden = !data.findings_truncated;
  document.getElementById("detail").hidden = true;
  paint();
}
document.getElementById("dashboard").addEventListener("click", (event) => {
  const tab = event.target.closest("[data-tab]");
  if (tab) {
    document.querySelectorAll("[data-tab]").forEach((button) => button.classList.toggle("active", button === tab));
    ["picture", "update", "evidence"].forEach((name) => {
      document.getElementById("tab-" + name).hidden = name !== tab.dataset.tab;
    });
    return;
  }
  const tile = event.target.closest("[data-tile]");
  if (tile) {
    openTile(tile.dataset.tile);
    return;
  }
  const choice = event.target.closest("[data-filter]");
  if (choice && choice.dataset.filter) {
    filter = filter === choice.dataset.filter && choice.classList.contains("stat") ? "all" : choice.dataset.filter;
    paint();
  }
});
document.getElementById("q").addEventListener("input", () => {
  query = document.getElementById("q").value.trim().toLowerCase();
  paint();
});
document.getElementById("more-reading").addEventListener("click", () => {
  const box = document.getElementById("narrative");
  box.hidden = !box.hidden;
});
async function scan(path) {
  filter = "all";
  status.className = "";
  status.textContent = "Scanning " + path + " …";
  scanBtn.disabled = true;
  dashboard.hidden = true;
  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path })
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Scan failed");
    status.textContent = "Scan finished. Click a color to focus the story.";
    render(data);
  } catch (error) {
    status.className = "error";
    status.textContent = error.message;
  } finally {
    scanBtn.disabled = false;
  }
}
document.getElementById("scan-form").addEventListener("submit", (event) => {
  event.preventDefault();
  scan(input.value.trim());
});
document.getElementById("sample-btn").addEventListener("click", () => {
  input.value = SAMPLE;
  scan(SAMPLE);
});
if (input.value.trim()) scan(input.value.trim());

const chat = document.getElementById("chat");
const chatLog = document.getElementById("chat-log");
let chatReady = false;
function addBubble(role, text) {
  const bubble = document.createElement("div");
  bubble.className = "bubble " + role;
  bubble.textContent = text;
  chatLog.appendChild(bubble);
  chatLog.scrollTop = chatLog.scrollHeight;
  return bubble;
}
function openChat() {
  chat.hidden = false;
  document.getElementById("ask-open").hidden = true;
  if (!chatReady) {
    chatReady = true;
    addBubble("bot", "Ask about this folder. I can explain a color, a practice such as MD5, what to update first, or what this scan does not prove.");
  }
  document.getElementById("ask-input").focus();
}
async function askQuestion(question) {
  const text = question.trim();
  if (!text) return;
  addBubble("user", text);
  const pending = addBubble("bot", "Looking at this scan…");
  try {
    const response = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: text })
    });
    const data = await response.json();
    pending.textContent = data.answer || data.error || "No answer.";
  } catch (error) {
    pending.textContent = error.message;
  }
}
document.getElementById("ask-open").addEventListener("click", openChat);
document.getElementById("ask-close").addEventListener("click", () => {
  chat.hidden = true;
  document.getElementById("ask-open").hidden = false;
});
document.getElementById("ask-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const box = document.getElementById("ask-input");
  askQuestion(box.value);
  box.value = "";
});
document.querySelectorAll("[data-ask]").forEach((button) => {
  button.addEventListener("click", () => {
    openChat();
    askQuestion(button.dataset.ask);
  });
});
</script>
</body>
</html>
"""


def render_platform(default_path: str, sample_path: str | None = None) -> str:
    sample = sample_path or str(_SAMPLE)
    return _PAGE.replace("__DEFAULT_PATH__", _esc(default_path)).replace("__SAMPLE_JSON__", json.dumps(sample))


def _esc(value: object) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def sandbox_message(profile: str) -> str:
    try:
        provider = ClassicalProvider(profile)
    except UnsupportedProfile as exc:
        return str(exc) + " This refusal is intentional. The sandbox does not make any system quantum-safe."
    message = b"evaluator-demo"
    if "sign" in provider.capabilities():
        signature = provider.sign(message)
        verified = provider.verify(message, signature)
        return (
            f"Profile {provider.profile_id} used library {provider.library}. "
            f"Sign and verify succeeded: {verified}. "
            "The caller used the same methods for every classical profile. "
            "This round-trip does not make any system quantum-safe."
        )
    token = provider.protect(message, b"pqcscan")
    opened = provider.open(token, b"pqcscan") == message
    return (
        f"Profile {provider.profile_id} used library {provider.library}. "
        f"Encrypt and open succeeded: {opened}. "
        "This round-trip does not make any system quantum-safe."
    )


def serve_platform(scan_root: Path, host: str = "127.0.0.1", port: int = 8765) -> None:
    page = render_platform(str(scan_root.resolve())).encode("utf-8")
    latest: dict[str, dict | None] = {"analysis": None}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/sandbox":
                profile = parse_qs(parsed.query).get("profile", ["ecdsa-p256"])[0]
                self._json(200, {"message": sandbox_message(profile)})
                return
            if parsed.path == "/api/scan":
                raw = parse_qs(parsed.query).get("path", [""])[0]
                self._scan(raw)
                return
            if parsed.path not in {"/", "/index.html"}:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)

        def do_POST(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path not in {"/api/scan", "/api/ask"}:
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", "0") or "0")
            if length > 8192:
                self._json(400, {"error": "That request is too long."})
                return
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                document = json.loads(raw_body) if raw_body else {}
            except json.JSONDecodeError:
                self._json(400, {"error": "Send a JSON object."})
                return
            if not isinstance(document, dict):
                self._json(400, {"error": "Send a JSON object."})
                return
            if parsed.path == "/api/ask":
                self._ask(str(document.get("question", "")))
                return
            self._scan(str(document.get("path", "")))

        def _ask(self, question: str) -> None:
            if not question.strip():
                self._json(400, {"error": "Type a question."})
                return
            with lock:
                analysis = latest["analysis"]
            if analysis is None:
                self._json(400, {"error": "Scan a folder first."})
                return
            self._json(200, {"answer": answer_question(analysis, question)})

        def _scan(self, raw: str) -> None:
            if not raw.strip():
                self._json(400, {"error": "Enter a folder path."})
                return
            try:
                payload = analyze_directory(raw)
            except ScanRequestError as exc:
                self._json(400, {"error": str(exc)})
                return
            with lock:
                latest["analysis"] = payload
            self._json(200, payload)

        def log_message(self, fmt: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Dashboard at http://{host}:{port}", flush=True)
    print(DISCLAIMER, flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
