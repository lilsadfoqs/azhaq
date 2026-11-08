"use strict";
// azhaq ui: the kept runs, each as three sentences and its graph on a canvas.
// Every number shown is the run's own summary or a count of its workspace and ledger.

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
};
const getJSON = async (url) => {
  const r = await fetch(url);
  const body = await r.json();
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
};
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || one + "s"}`;

// Columns, left to right: who owns it, the names, the addresses, the services, what they serve.
const RANK = {
  Organization: 0, ASN: 0, Prefix: 1, Domain: 2, Hostname: 3, IPAddress: 4, Port: 5,
  Application: 6, URL: 6, Certificate: 6, Email: 6, CloudAccount: 6,
};
const TYPE_NAME = {
  Organization: "organizations", ASN: "ASNs", Prefix: "prefixes", Domain: "domains", Hostname: "hosts",
  IPAddress: "addresses", Port: "ports", Application: "web services", URL: "routes", Certificate: "certificates",
  Email: "emails", CloudAccount: "cloud accounts",
};
const TYPE_ONE = {
  Organization: "organization", ASN: "ASN", Prefix: "prefix", Domain: "domain", Hostname: "host",
  IPAddress: "address", Port: "port", Application: "web service", URL: "route", Certificate: "certificate",
  Email: "email", CloudAccount: "cloud account",
};
const FOLD_OVER = 8; // a host with more routes than this shows them as one node until opened
const NODE_W = 230, NODE_H = 24, COL_GAP = 300, ROW_GAP = 32;

let current = null; // { id, graph, nodes, edges, expanded:Set, layout }
let view = { s: 1, x: 40, y: 40 };
let hover = null, searchHits = new Set();

// ---------- runs list ----------
async function loadRuns() {
  const data = await getJSON("/api/runs");
  $("home").textContent = data.home;
  const ol = $("runlist");
  ol.replaceChildren();
  if (!data.runs.length) {
    ol.append(el("li", "muted", "No runs kept yet: run a command (azhaq run, subs, ports…) and reload."));
    return;
  }
  for (const r of data.runs) {
    const li = el("li");
    li.dataset.id = r.id;
    const t = el("div", "t", r.target || "(no target)");
    const st = el("span", "badge " + (r.status === "ok" ? "ok" : r.status === "running" ? "" : "bad"), r.status);
    t.append(st);
    li.append(t);
    li.append(el("div", "m", `${r.command} · ${new Date(r.started).toLocaleString()} · ${r.time}`));
    li.append(el("div", "m", `requests: ${r.requests} · ${r.got}`));
    li.onclick = () => selectRun(r.id);
    ol.append(li);
  }
  const want = decodeURIComponent(location.hash.slice(1));
  selectRun(data.runs.some((r) => r.id === want) ? want : data.runs[0].id);
}

async function selectRun(id) {
  location.hash = encodeURIComponent(id);
  for (const li of $("runlist").children) li.classList.toggle("on", li.dataset.id === id);
  closePanel();
  $("story").replaceChildren(el("p", "muted", "Reading the run…"));
  const [run, graph] = await Promise.all([getJSON(`/api/runs/${encodeURIComponent(id)}`), getJSON(`/api/runs/${encodeURIComponent(id)}/graph`)]);
  current = { id, run, graph, expanded: new Set() };
  renderStory(run, graph);
  relayout(true);
}

// ---------- the three sentences ----------
function renderStory(run, graph) {
  const rec = run.record;
  const s = rec.summary || null;
  const box = $("story");
  box.replaceChildren();
  const line = (label, text) => {
    const p = el("p");
    p.append(el("b", null, label), document.createTextNode(" " + text));
    box.append(p);
  };
  line("Asked", `azhaq ${rec.command} ${rec.args.join(" ")}`.trim() + (rec.target ? ` (pointed at ${rec.target})` : ""));

  let did;
  const L = run.ledger;
  if (L) {
    const parts = [];
    parts.push(plural(L.by_class.target || 0, "request") + ` to ${plural(L.hosts.length, "target host")}`);
    if (L.by_class.source) parts.push(`${L.by_class.source} to ${plural(L.sources.length, "third-party source")}`);
    if (L.by_class.dns) parts.push(plural(L.by_class.dns, "DNS query", "DNS queries"));
    did = parts.join(", ");
  } else if (s) {
    did = plural(s.requests || 0, "request") + " to targets" + (s.dns_queries ? `, ${plural(s.dns_queries, "DNS query", "DNS queries")}` : "") + " (the summary's count; no ledger kept)";
  } else {
    did = "what it sent was not recorded";
  }
  did += `, in ${run.time}. `;
  did += run.status === "ok" ? "It finished with nothing failed." :
    run.status === "running" ? "It is still running." :
    run.status === "did not finish" ? "It did not finish: the process stopped before it could say how it ended." :
    `It ended with ${run.status}: ${run.exit_meaning || ""}`;
  line("Did", did);

  const nodes = graph.nodes || [];
  if (nodes.length) {
    const by = {}, fresh = {};
    let leads = 0;
    for (const n of nodes) {
      by[n.type] = (by[n.type] || 0) + 1;
      if (n.new) fresh[n.type] = (fresh[n.type] || 0) + 1;
      if (n.lead) leads++;
    }
    const order = Object.keys(by).sort((a, b) => (RANK[a] ?? 9) - (RANK[b] ?? 9));
    const got = order.map((t) => `${by[t]} ${by[t] === 1 ? TYPE_ONE[t] || t : TYPE_NAME[t] || t}` + (fresh[t] && fresh[t] !== by[t] ? ` (${fresh[t]} new)` : ""));
    if (nodes.every((n) => n.new)) got.push("all first seen in this run");
    const hints = nodes.filter((n) => n.hint && !n.lead).length;
    line("Got", got.join(", ") + (leads ? `; ${plural(leads, "finding or lead", "findings or leads")} in red` : "; no findings or leads") +
      (hints ? `; ${plural(hints, "map hint")} (places to look, not findings)` : ""));
  } else if (s && s.counts) {
    line("Got", Object.entries(s.counts).map(([k, v]) => `${v} ${k}`).join(", ") + (graph.note ? ` (${graph.note})` : ""));
  } else {
    line("Got", graph.note || "nothing recorded");
  }
  if (rec.error) box.append(el("p", "muted", "Error: " + rec.error));

  const more = el("details");
  more.append(el("summary", null, "Details"));
  const ul = el("ul");
  const li = (t) => ul.append(el("li", null, t));
  li("Folder: " + run.dir);
  if (rec.workspace) li("Workspace: " + rec.workspace);
  for (const w of rec.wrote || []) li("Wrote: " + w);
  if (L) {
    for (const [k, v] of Object.entries(L.by_purpose).sort((a, b) => b[1] - a[1])) li(`${v} requests for ${k}`);
    for (const h of L.hosts.slice(0, 20)) li(`${h.count} → ${h.name}`);
    if (L.hosts.length > 20) li(`… and ${L.hosts.length - 20} more hosts`);
    for (const h of L.sources) li(`${h.count} → ${h.name} (third party)`);
  } else if (run.ledger_error) li(run.ledger_error);
  if (s && s.failed) for (const f of s.failed) li(`failed: ${f.collector}: ${f.error}` + (f.count > 1 ? ` (×${f.count})` : ""));
  if (s && s.notes) for (const n of s.notes) li("note: " + n);
  if (s && s.next) for (const n of s.next) li("next: " + n);
  more.append(ul);
  box.append(more);
}

// ---------- graph model: folding and layout ----------
function hostOfURL(u) {
  try { return new URL(u).hostname; } catch { return ""; }
}

function buildModel() {
  const { graph, expanded } = current;
  const nodes = new Map();
  for (const n of graph.nodes) nodes.set(n.id, { ...n });
  const adj = new Map();
  const link = (a, b) => {
    if (!adj.has(a)) adj.set(a, new Set());
    if (!adj.has(b)) adj.set(b, new Set());
    adj.get(a).add(b); adj.get(b).add(a);
  };
  for (const e of graph.edges) if (nodes.has(e.from) && nodes.has(e.to)) link(e.from, e.to);

  // The routes of a host: a URL's neighbour that is a host, address or web service, else its own host name.
  const keyIndex = new Map();
  for (const n of nodes.values()) keyIndex.set(n.type + "\0" + n.key, n.id);
  // A route's parent is the host its own URL names; a link from another host is not its parent.
  const parentOf = (u) => {
    const h = hostOfURL(u.key).replace(/^\[|\]$/g, "");
    return keyIndex.get("Hostname\0" + h) || keyIndex.get("IPAddress\0" + h) || "";
  };
  const groups = new Map();
  for (const n of nodes.values()) {
    if (n.type !== "URL") continue;
    const p = parentOf(n) || "host:" + hostOfURL(n.key);
    if (!groups.has(p)) groups.set(p, []);
    groups.get(p).push(n);
  }
  // Many routes in all: fold every host's routes past two, so the hosts stay readable.
  const urlCount = [...nodes.values()].filter((n) => n.type === "URL").length;
  const foldOver = urlCount > 60 ? 2 : FOLD_OVER;
  const replace = new Map(); // node id -> fold node id
  const folds = [];
  for (const [p, list] of groups) {
    const noise = list.filter((n) => [401, 403, 404, 410].includes(n.status) && !n.lead);
    const rest = list.filter((n) => !noise.includes(n));
    const fold = (members, kind) => {
      const id = `fold:${kind}:${p}`;
      if (expanded.has(id) || members.length === 0) return;
      const leads = members.filter((m) => m.lead).length;
      const fresh = members.filter((m) => m.new).length;
      const host = nodes.has(p) ? nodes.get(p).key : p.replace(/^host:/, "");
      const label = (kind === "noise" ?
        `${members.length} forbidden or not found` :
        `${plural(members.length, "route")}` + (leads ? `, ${leads} lead` : "") + (fresh && fresh !== members.length ? `, ${fresh} new` : "")) +
        (host ? ` · ${host}` : "");
      folds.push({ id, type: "URL", key: label, fold: true, noise: kind === "noise", members: members.map((m) => m.id),
        lead: leads ? "lead" : "", new: fresh > 0, parent: p });
      for (const m of members) replace.set(m.id, id);
    };
    if (noise.length > 1) fold(noise, "noise");
    if (rest.length > foldOver) fold(rest, "routes");
  }
  // Names that led nowhere in this run (no address, nothing served) fold per domain.
  const leadsSomewhere = (n) => [...(adj.get(n.id) || [])].some((m) => ["IPAddress", "URL", "Application", "Port"].includes(nodes.get(m).type));
  const dead = new Map();
  for (const n of nodes.values()) {
    if (n.type !== "Hostname" || n.lead || leadsSomewhere(n)) continue;
    const dom = [...(adj.get(n.id) || [])].find((m) => nodes.get(m).type === "Domain") || "";
    if (!dead.has(dom)) dead.set(dom, []);
    dead.get(dom).push(n);
  }
  for (const [dom, list] of dead) {
    const id = "fold:dead:" + dom;
    if (list.length < 4 || expanded.has(id)) continue;
    folds.push({ id, type: "Hostname", key: `${list.length} names without an address`, fold: true, noise: true,
      members: list.map((m) => m.id), lead: "", new: list.some((m) => m.new), passive: list.every((m) => m.passive), parent: dom });
    for (const m of list) replace.set(m.id, id);
  }
  for (const f of folds) nodes.set(f.id, f);
  for (const id of replace.keys()) nodes.delete(id);
  const edgeSet = new Set();
  const edges = [];
  const addEdge = (a, b) => {
    a = replace.get(a) || a; b = replace.get(b) || b;
    if (a === b || !nodes.has(a) || !nodes.has(b)) return;
    const k = a < b ? a + "\0" + b : b + "\0" + a;
    if (edgeSet.has(k)) return;
    edgeSet.add(k);
    edges.push([a, b]);
  };
  for (const e of graph.edges) addEdge(e.from, e.to);
  for (const f of folds) if (nodes.has(f.parent)) addEdge(f.parent, f.id);
  return { nodes, edges };
}

function layout(model) {
  const cols = new Map();
  for (const n of model.nodes.values()) {
    const r = RANK[n.type] ?? 7;
    if (!cols.has(r)) cols.set(r, []);
    cols.get(r).push(n);
  }
  const ranks = [...cols.keys()].sort((a, b) => a - b);
  const nb = new Map();
  for (const [a, b] of model.edges) {
    if (!nb.has(a)) nb.set(a, []);
    if (!nb.has(b)) nb.set(b, []);
    nb.get(a).push(b); nb.get(b).push(a);
  }
  const pos = new Map();
  ranks.forEach((r, ci) => {
    cols.get(r).sort((a, b) => a.key.localeCompare(b.key));
    cols.get(r).forEach((n, i) => pos.set(n.id, { col: ci, row: i }));
  });
  // Barycenter sweeps: order each column by the mean row of its neighbours in the others.
  for (let pass = 0; pass < 4; pass++) {
    const seq = pass % 2 ? [...ranks].reverse() : ranks;
    for (const r of seq) {
      const col = cols.get(r);
      const bary = new Map();
      for (const n of col) {
        const rows = (nb.get(n.id) || []).map((m) => pos.get(m)).filter((p) => p && p.col !== pos.get(n.id).col).map((p) => p.row);
        bary.set(n.id, rows.length ? rows.reduce((a, b) => a + b, 0) / rows.length : pos.get(n.id).row);
      }
      col.sort((a, b) => bary.get(a.id) - bary.get(b.id) || a.key.localeCompare(b.key));
      col.forEach((n, i) => (pos.get(n.id).row = i));
    }
  }
  // Each column centred on the tallest one.
  const tallest = Math.max(1, ...ranks.map((r) => cols.get(r).length));
  for (const r of ranks) {
    const col = cols.get(r);
    const off = ((tallest - col.length) * ROW_GAP) / 2;
    for (const n of col) {
      const p = pos.get(n.id);
      n.x = p.col * COL_GAP;
      n.y = off + p.row * ROW_GAP;
    }
  }
  return { cols: ranks.length, height: tallest * ROW_GAP };
}

function relayout(fit) {
  const model = buildModel();
  const box = layout(model);
  current.model = model;
  // When everything is new (a workspace with one run), the outline would say nothing.
  current.allNew = current.graph.nodes.length > 0 && current.graph.nodes.every((n) => n.new);
  current.box = box;
  current.adj = new Map();
  for (const [a, b] of model.edges) {
    if (!current.adj.has(a)) current.adj.set(a, new Set());
    if (!current.adj.has(b)) current.adj.set(b, new Set());
    current.adj.get(a).add(b); current.adj.get(b).add(a);
  }
  const empty = $("empty");
  empty.hidden = model.nodes.size > 0;
  empty.textContent = current.graph.note || "This run kept nothing to draw.";
  if (fit) fitView();
  draw();
}

// ---------- drawing ----------
const canvas = $("canvas");
const ctx = canvas.getContext("2d");
const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();

function resize() {
  const r = canvas.getBoundingClientRect();
  const d = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, r.width * d);
  canvas.height = Math.max(1, r.height * d);
  draw();
}

function fitView() {
  if (!current || !current.box) return;
  const r = canvas.getBoundingClientRect();
  const w = Math.max(1, current.box.cols * COL_GAP - (COL_GAP - NODE_W));
  const h = Math.max(1, current.box.height);
  const s = Math.min(1.4, Math.max(0.08, Math.min((r.width - 60) / w, (r.height - 60) / h)));
  view = { s, x: (r.width - w * s) / 2, y: Math.max(20, (r.height - h * s) / 2) };
}

function label(n) {
  let t = n.fold ? n.key : n.type === "URL" ? shortURL(n.key) : n.key;
  if (n.type === "Port" && !n.fold) t = "port " + t;
  if (n.status && !n.fold) t += "  " + n.status;
  return t.length > 34 ? t.slice(0, 33) + "…" : t;
}
function shortURL(u) {
  try { const x = new URL(u); return (x.pathname + x.search) || "/"; } catch { return u; }
}

function draw() {
  const d = window.devicePixelRatio || 1;
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  if (!current || !current.model) return;
  ctx.setTransform(view.s * d, 0, 0, view.s * d, view.x * d, view.y * d);
  const C = { fg: css("--fg"), muted: css("--muted"), line: css("--line"), card: css("--card"), accent: css("--accent"),
    lead: css("--lead"), leadbg: css("--leadbg"), fold: css("--fold"), edge: css("--edge"), hi: css("--hi") };
  const r = canvas.getBoundingClientRect();
  const vx0 = -view.x / view.s - NODE_W, vy0 = -view.y / view.s - NODE_H;
  const vx1 = (r.width - view.x) / view.s, vy1 = (r.height - view.y) / view.s;
  const inView = (n) => n.x >= vx0 && n.x <= vx1 && n.y >= vy0 && n.y <= vy1;
  const { nodes, edges } = current.model;
  const near = hover ? current.adj.get(hover) || new Set() : null;

  ctx.lineWidth = 1 / Math.max(view.s, 0.5);
  for (const [a, b] of edges) {
    const A = nodes.get(a), B = nodes.get(b);
    if (!inView(A) && !inView(B)) continue;
    const L = A.x <= B.x ? A : B, R = A.x <= B.x ? B : A;
    const lit = hover && (a === hover || b === hover);
    ctx.strokeStyle = lit ? C.accent : C.edge;
    ctx.globalAlpha = hover && !lit ? 0.25 : 1;
    ctx.beginPath();
    const x1 = L.x + NODE_W, y1 = L.y + NODE_H / 2, x2 = R.x, y2 = R.y + NODE_H / 2;
    if (L.x === R.x) { ctx.moveTo(L.x + NODE_W, y1); ctx.lineTo(R.x + NODE_W, y2); } else {
      const mx = (x1 + x2) / 2;
      ctx.moveTo(x1, y1); ctx.bezierCurveTo(mx, y1, mx, y2, x2, y2);
    }
    ctx.stroke();
  }
  ctx.globalAlpha = 1;
  const small = view.s < 0.35;
  ctx.font = "12px system-ui, -apple-system, 'Segoe UI', sans-serif";
  ctx.textBaseline = "middle";
  for (const n of nodes.values()) {
    if (!inView(n)) continue;
    const dim = hover && n.id !== hover && !near.has(n.id);
    ctx.globalAlpha = dim ? 0.3 : 1;
    ctx.fillStyle = n.lead ? C.leadbg : n.fold ? C.line : C.card;
    const fresh = n.new && !current.allNew;
    ctx.strokeStyle = n.lead ? C.lead : fresh ? C.accent : n.fold ? C.fold : C.muted;
    ctx.lineWidth = (n.lead || fresh ? 2 : 1) / Math.max(view.s, 0.5);
    ctx.setLineDash(n.passive ? [4, 3] : []);
    ctx.beginPath();
    ctx.roundRect(n.x, n.y, NODE_W, NODE_H, 6);
    ctx.fill(); ctx.stroke();
    ctx.setLineDash([]);
    if (n.hint && !n.lead) { // a map hint: a small dot, not a finding's colour
      ctx.fillStyle = C.hi; ctx.beginPath(); ctx.arc(n.x + NODE_W - 9, n.y + NODE_H / 2, 3.5, 0, 7); ctx.fill();
    }
    if (searchHits.has(n.id)) {
      ctx.strokeStyle = C.hi; ctx.lineWidth = 3 / Math.max(view.s, 0.5);
      ctx.strokeRect(n.x - 3, n.y - 3, NODE_W + 6, NODE_H + 6);
    }
    if (!small) {
      ctx.fillStyle = n.noise ? C.muted : n.lead ? C.lead : C.fg;
      ctx.fillText(label(n), n.x + 8, n.y + NODE_H / 2, NODE_W - 16);
    }
  }
  ctx.globalAlpha = 1;
  // Column headings.
  if (!small) {
    const seen = new Map();
    for (const n of nodes.values()) if (!seen.has(n.x)) seen.set(n.x, n.type);
    ctx.fillStyle = C.muted;
    for (const [x, t] of seen) {
      const types = new Set([...nodes.values()].filter((n) => n.x === x).map((n) => TYPE_NAME[n.type] || n.type));
      ctx.fillText([...types].join(" · "), x, -14);
    }
  }
}

// ---------- interaction ----------
function at(ev) {
  const r = canvas.getBoundingClientRect();
  const x = (ev.clientX - r.left - view.x) / view.s, y = (ev.clientY - r.top - view.y) / view.s;
  if (!current || !current.model) return null;
  for (const n of current.model.nodes.values()) if (x >= n.x && x <= n.x + NODE_W && y >= n.y && y <= n.y + NODE_H) return n;
  return null;
}
let drag = null;
canvas.addEventListener("mousedown", (ev) => { drag = { x: ev.clientX, y: ev.clientY, vx: view.x, vy: view.y, moved: false }; canvas.classList.add("drag"); });
window.addEventListener("mouseup", (ev) => {
  canvas.classList.remove("drag");
  if (drag && !drag.moved) { const n = at(ev); if (n) openNode(n); }
  drag = null;
});
window.addEventListener("mousemove", (ev) => {
  if (drag) {
    const dx = ev.clientX - drag.x, dy = ev.clientY - drag.y;
    if (Math.abs(dx) + Math.abs(dy) > 3) drag.moved = true;
    view.x = drag.vx + dx; view.y = drag.vy + dy; draw();
    return;
  }
  if (ev.target !== canvas) return;
  const n = at(ev);
  const id = n ? n.id : null;
  canvas.title = n ? (n.fold ? n.key + " (click to open)" : `${n.type}: ${n.key}`) : "";
  if (id !== hover) { hover = id; draw(); }
});
canvas.addEventListener("wheel", (ev) => {
  ev.preventDefault();
  const r = canvas.getBoundingClientRect();
  const mx = ev.clientX - r.left, my = ev.clientY - r.top;
  const k = Math.exp(-ev.deltaY * 0.0015);
  const s = Math.min(3, Math.max(0.03, view.s * k));
  view.x = mx - ((mx - view.x) * s) / view.s; view.y = my - ((my - view.y) * s) / view.s; view.s = s;
  draw();
}, { passive: false });
window.addEventListener("resize", resize);
$("fit").onclick = () => { fitView(); draw(); };
$("unfold").onclick = () => {
  if (!current) return;
  for (const n of current.model.nodes.values()) if (n.fold) current.expanded.add(n.id);
  relayout(true);
};
$("search").addEventListener("input", (ev) => {
  const q = ev.target.value.trim().toLowerCase();
  searchHits = new Set();
  if (q && current) {
    for (const n of current.graph.nodes) {
      if (!n.key.toLowerCase().includes(q)) continue;
      // A hit inside a folded group opens that group.
      for (const f of current.model.nodes.values()) if (f.fold && f.members.includes(n.id)) current.expanded.add(f.id);
      searchHits.add(n.id);
    }
    relayout(false);
    const first = [...searchHits].map((id) => current.model.nodes.get(id)).find(Boolean);
    if (first) {
      const r = canvas.getBoundingClientRect();
      view.x = r.width / 2 - (first.x + NODE_W / 2) * view.s; view.y = r.height / 2 - first.y * view.s;
    }
  }
  draw();
});

// ---------- side panel ----------
function closePanel() { $("panel").hidden = true; }
$("close").onclick = closePanel;

async function openNode(n) {
  if (n.fold) {
    current.expanded.add(n.id);
    relayout(false);
    return;
  }
  $("panel").hidden = false;
  $("ptitle").textContent = n.key;
  const body = $("pbody");
  body.replaceChildren(el("p", "muted", "Reading…"));
  let data;
  try {
    data = await getJSON(`/api/runs/${encodeURIComponent(current.id)}/node/${encodeURIComponent(n.id)}`);
  } catch (e) {
    body.replaceChildren(el("p", null, e.message));
    return;
  }
  body.replaceChildren();
  const e = data.entity;
  const facts = [
    ["Type", e.type],
    ["First seen", new Date(e.first_seen).toLocaleString()],
    ["Last seen", new Date(e.last_seen).toLocaleString()],
    ["In this run", n.new ? "new: first seen while this run ran" : "seen before this run"],
  ];
  if (n.lead) facts.push(["Label", n.lead]);
  if (n.hint) facts.push(["Map hint", n.hint + " (a place to look, not a finding)"]);
  if (n.status) facts.push(["Status", String(n.status)]);
  for (const [k, v] of facts) {
    const p = el("p");
    p.append(el("b", null, k + ": "), document.createTextNode(v));
    body.append(p);
  }
  if (data.curl) {
    body.append(el("p", null, "Check it by hand:"));
    body.append(el("pre", null, data.curl));
  }
  const obs = data.observations || [];
  body.append(el("p", "muted", `${plural(obs.length, "observation")}: what saw it, from where, and what it recorded (secrets masked).`));
  for (const o of obs) {
    const d = el("div", "obs");
    d.append(el("div", null, `${o.collector} · ${o.kind}${o.passive ? " · third-party source" : ""}`));
    d.append(el("div", "muted", `${o.source} · ${new Date(o.observed_at).toLocaleString()}`));
    d.append(el("pre", null, JSON.stringify(o.payload, null, 2)));
    body.append(d);
  }
}

resize();
loadRuns().catch((e) => $("story").replaceChildren(el("p", null, "Could not read the runs: " + e.message)));

// Shell controls retain the original application IDs and API code.
(() => {
  const root = document.documentElement, theme = document.getElementById('theme');
  const saved = (() => { try { return localStorage.getItem('azhaq-ui-theme') || 'system'; } catch { return 'system'; } })();
  function applyTheme(value) {
    if (value === 'system') delete root.dataset.theme; else root.dataset.theme = value;
    theme.value = value;
    try { localStorage.setItem('azhaq-ui-theme', value); } catch {}
    window.dispatchEvent(new Event('resize'));
  }
  applyTheme(['system','light','dark'].includes(saved) ? saved : 'system');
  theme.addEventListener('change', () => applyTheme(theme.value));
  const runs = document.getElementById('collapse-runs');
  runs.addEventListener('click', () => {
    const mobile = matchMedia('(max-width:720px)').matches;
    const open = mobile ? document.body.classList.toggle('mobile-runs') : !document.body.classList.toggle('runs-collapsed');
    runs.setAttribute('aria-expanded', String(open));
    window.dispatchEvent(new Event('resize'));
  });
  const story = document.getElementById('collapse-story');
  story.addEventListener('click', () => {
    const open = !document.body.classList.toggle('story-collapsed');
    story.setAttribute('aria-expanded', String(open));
    window.dispatchEvent(new Event('resize'));
  });
})();
