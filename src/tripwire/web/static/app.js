// Tripwire dashboard. Everything from the API is untrusted (it comes out of
// package archives), so it is only ever written with textContent.
"use strict";

const PAGE = 50;
const state = { offset: 0, total: 0, timer: null, openIds: new Set() };
const $ = (id) => document.getElementById(id);
const form = $("filters");

function el(tag, cls, text) {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined && text !== null) n.textContent = String(text);
  return n;
}

function params(offset) {
  const fd = new FormData(form);
  const p = new URLSearchParams();
  for (const key of ["ecosystem", "analyzer", "q"]) {
    const v = (fd.get(key) || "").trim();
    if (v) p.set(key, v);
  }
  const min = Number(fd.get("min_score") || 0);
  if (min > 0) p.set("min_score", String(min));
  if (fd.get("flagged")) p.set("flagged", "true");
  p.set("limit", String(PAGE));
  p.set("offset", String(offset));
  return p;
}

function ago(iso) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return `${Math.round(s)}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function renderRow(r) {
  const li = $("row-tpl").content.firstElementChild.cloneNode(true);
  li.dataset.id = r.id;
  if (r.flagged) li.classList.add("flagged");
  const score = li.querySelector(".score");
  if (r.status === "scanned") {
    score.textContent = r.score;
    score.classList.add(r.level);
    score.title = `risk ${r.score}/100 (${r.level})`;
  } else {
    score.textContent = r.status;
    score.classList.add("err");
  }
  li.querySelector(".name").textContent = r.name;
  li.querySelector(".ver").textContent = r.version;
  li.querySelector(".eco").textContent = r.ecosystem;
  li.querySelector(".why").textContent = r.status === "scanned" ? r.explanation : (r.status_detail || "");
  const chips = li.querySelector(".chips");
  for (const a of (r.analyzers || "").split(",").filter(Boolean)) chips.append(el("span", "chip", a));
  const when = li.querySelector(".when");
  when.textContent = ago(r.scanned_at);
  when.title = r.scanned_at;
  const head = li.querySelector(".head");
  const detail = li.querySelector(".detail");
  head.addEventListener("click", () => toggle(r, head, detail));
  if (state.openIds.has(r.id)) toggle(r, head, detail);
  return li;
}

async function toggle(r, head, detail) {
  const open = head.getAttribute("aria-expanded") === "true";
  if (open) {
    head.setAttribute("aria-expanded", "false");
    detail.hidden = true;
    state.openIds.delete(r.id);
    return;
  }
  state.openIds.add(r.id);
  head.setAttribute("aria-expanded", "true");
  detail.hidden = false;
  detail.replaceChildren(el("p", "w", "Loading evidence..."));
  try {
    const res = await fetch(`/api/releases/${encodeURIComponent(r.id)}`);
    const data = await res.json();
    const items = (data.findings || []);
    if (!items.length) {
      detail.replaceChildren(el("p", "w", "No evidence recorded for this release."));
      return;
    }
    const frag = document.createDocumentFragment();
    for (const f of items) {
      const row = el("div", "ev");
      row.append(el("span", "w", Number(f.weight).toFixed(2)));
      const body = el("div");
      body.append(el("div", "msg", f.message));
      const loc = [f.analyzer + "/" + f.rule];
      if (f.file) loc.push(f.line ? `${f.file}:${f.line}` : f.file);
      body.append(el("div", "loc", loc.join("  ")));
      row.append(body);
      if (f.snippet) row.append(el("code", "", f.snippet));
      frag.append(row);
    }
    detail.replaceChildren(frag);
  } catch (e) {
    detail.replaceChildren(el("p", "w", "Could not load evidence."));
  }
}

async function load(reset = true) {
  const offset = reset ? 0 : state.offset;
  const res = await fetch(`/api/releases?${params(offset)}`);
  if (!res.ok) return;
  const data = await res.json();
  const feed = $("feed");
  const rows = data.items.map(renderRow);
  if (reset) feed.replaceChildren(...rows); else feed.append(...rows);
  state.offset = offset + data.items.length;
  state.total = data.total;
  $("count").textContent = `${data.total} release${data.total === 1 ? "" : "s"} · newest first`;
  $("more").hidden = state.offset >= data.total;
  $("empty").hidden = data.total !== 0;
}

async function loadStats() {
  try {
    const res = await fetch("/api/stats");
    const s = await res.json();
    const box = $("stats");
    let scanned = 0, flagged = 0;
    for (const e of Object.values(s.by_ecosystem || {})) { scanned += e.scanned || 0; flagged += e.flagged || 0; }
    const tiles = [["scanned", scanned], ["flagged", flagged]];
    for (const [eco, e] of Object.entries(s.by_ecosystem || {})) tiles.push([eco, `${e.flagged || 0} / ${e.scanned || 0}`]);
    box.replaceChildren(...tiles.map(([label, v]) => {
      const t = el("div", "stat"); t.append(el("b", "", v), el("span", "", label)); return t;
    }));
    const sel = $("analyzer");
    if (sel.options.length === 1) for (const a of s.analyzers || []) sel.append(new Option(a, a));
  } catch (e) { /* stats are optional */ }
}

function schedule() {
  clearInterval(state.timer);
  if (form.elements.live.checked) {
    state.timer = setInterval(() => { if (!document.hidden) { load(true); loadStats(); } }, 5000);
  }
}

let debounce;
form.addEventListener("input", (e) => {
  $("minv").textContent = form.elements.min_score.value;
  if (e.target.name === "live") return schedule();
  clearTimeout(debounce);
  debounce = setTimeout(() => load(true), 200);
});
form.addEventListener("submit", (e) => e.preventDefault());
$("more").addEventListener("click", () => load(false));

loadStats();
load(true);
schedule();
