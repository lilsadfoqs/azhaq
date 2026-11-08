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
let hover = null, searchHits = new Set(), selectedGraph = null, graphMode = "results", executionNodes = [];

// ---------- runs list ----------
async function loadRuns() {
  const data = await getJSON("/api/runs");
  const home = String(data.home || '');
  const parts = home.split('/').filter(Boolean);
  $('home').textContent = parts.length > 2 ? '…/' + parts.slice(-2).join('/') : home;
  $('home').title = home;
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
  selectedGraph = null;
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
    did = (s.requests == null ? "requests not recorded" : plural(s.requests, "request") + " to targets") + (s.dns_queries ? `, ${plural(s.dns_queries, "DNS query", "DNS queries")}` : "") + " (the summary's count; no ledger kept)";
  } else {
    did = "what it sent was not recorded";
  }
  did += `, in ${run.time}. `;
  did += run.status === "ok" ? "It finished: " + (run.exit_meaning || "exit 0") :
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
  if (graphMode === "execution") { drawExecution(); return; }
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
    ctx.strokeStyle = n.lead ? C.lead : n.fold ? C.fold : C.muted;
    ctx.lineWidth = (n.lead || n.id === selectedGraph ? 2 : 1) / Math.max(view.s, 0.5);
    ctx.setLineDash(n.passive ? [4, 3] : []);
    ctx.beginPath();
    ctx.roundRect(n.x, n.y, NODE_W, NODE_H, 6);
    ctx.fill(); ctx.stroke();
    ctx.setLineDash([]);
    if (fresh) { ctx.strokeStyle=C.accent;ctx.lineWidth=2/Math.max(view.s,.5);ctx.beginPath();ctx.moveTo(n.x+2,n.y+4);ctx.lineTo(n.x+2,n.y+NODE_H-4);ctx.stroke(); }
    if (n.id === selectedGraph) { ctx.strokeStyle=C.accent;ctx.lineWidth=2/Math.max(view.s,.5);ctx.strokeRect(n.x-3,n.y-3,NODE_W+6,NODE_H+6); }
    if (n.hint && !n.lead) { // a map hint: a small dot, not a finding's colour
      ctx.fillStyle = C.hi; ctx.beginPath(); ctx.arc(n.x + NODE_W - 9, n.y + NODE_H / 2, 3.5, 0, 7); ctx.fill();
    }
    if (searchHits.has(n.id)) {
      ctx.strokeStyle = C.hi; ctx.lineWidth = 3 / Math.max(view.s, 0.5);
      ctx.strokeRect(n.x - 3, n.y - 3, NODE_W + 6, NODE_H + 6);
    }
    if (!small) {
      ctx.fillStyle = n.noise ? C.muted : n.lead ? C.lead : C.fg;
      const caps=Array.isArray(n.capabilities)?n.capabilities.filter(id=>CAP_PATHS[id]):[];
      if(caps.length){ ctx.save();ctx.translate(n.x+6,n.y+5);ctx.scale(.5,.5);ctx.strokeStyle=C.fg;ctx.lineWidth=2;ctx.stroke(new Path2D(CAP_PATHS[caps[0]]));ctx.restore(); }
      const suffix=caps.length>1?' +'+(caps.length-1):'';
      ctx.fillText(label(n)+suffix, n.x + (caps.length?26:8), n.y + NODE_H / 2, NODE_W-(caps.length?34:16));
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
  if (graphMode === 'execution') { const x=ev.clientX-r.left,y=ev.clientY-r.top; return executionNodes.find(n=>Math.hypot(x-n.x,y-n.y)<n.radius)||null; }
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
function closePanel() { $("panel").hidden = true; if (graphMode === "execution") requestAnimationFrame(resize); }
$("close").onclick = closePanel;

async function openNode(n) {
  if (n.execution) { showExecution(n); return; }
  selectedGraph = n.id;
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
  const attributed=[...new Set(obs.map(o=>COLLECTOR_CAP[o.collector]).filter(Boolean))].sort((a,b)=>CAPABILITIES.findIndex(c=>c.id===a)-CAPABILITIES.findIndex(c=>c.id===b));
  if(attributed.length){ n.capabilities=attributed; const graphNode=current.graph.nodes.find(x=>x.id===n.id);if(graphNode)graphNode.capabilities=attributed;draw(); }
  body.append(el("p", "muted", `${plural(obs.length, "observation")}: what saw it, from where, and what it recorded (secrets masked).`));
  for (const o of obs) {
    const d = el("div", "obs");
    d.append(el("div", null, `${o.collector} · ${o.kind}${o.passive ? " · third-party source" : ""}`));
    d.append(el("div", "muted", `${o.source} · ${new Date(o.observed_at).toLocaleString()}`));
    d.append(el("pre", null, JSON.stringify(o.payload, null, 2)));
    body.append(d);
  }
}


// Capability attribution is read from observations or explicit node metadata; never infer it from an entity type.
const CAPABILITIES = [{"id":"sources","name":"Sources","description":"Query public sources for names, archived URLs, ownership and search records.","description_words":11,"replaces":["subfinder","gau"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M4 5h4v4H4Z M4 19h4v4H4Z M20 12h4v4h-4Z M8 7h5l5 7h2 M8 21h5l5-7","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Converging sources","collectors":["subdomains","urls","rdap","search"],"commands":["subs","urls"],"capability_color":null},{"id":"names","name":"Names","description":"Resolve names; expand subdomains; find ASN prefixes and reverse DNS names.","description_words":11,"replaces":["dnsx","asnmap"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M11 3h6v6h-6Z M4 19h6v6H4Z M18 19h6v6h-6Z M14 9v5 M7 19v-5h14v5","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Name hierarchy","collectors":["dns","dns-brute","permute","asn","prefix","ptr"],"commands":["dns","asn","subs -live"],"capability_color":null},{"id":"web","name":"Web","description":"Inspect HTTP and TLS; find routes in pages, scripts and API specs.","description_words":12,"replaces":["httpx","katana","jsluice"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M4 4h16l4 4v16H4Z M4 10h20 M9 7h1 M8 17h4l3-3h5 M12 17l3 4h5","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Browser and branching routes","collectors":["http","paths","crawl","js","render","tls","openapi","graphql","graphql-schema"],"commands":["run","probe","crawl"],"capability_color":null},{"id":"ports","name":"Ports","description":"Find open TCP and UDP ports and identify their services.","description_words":10,"replaces":["naabu","nmap (port and service discovery)"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M4 5h20v7H4Z M4 17h20v7H4Z M9 8v1 M19 8v1 M9 20v1 M19 20v1","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Paired service sockets","collectors":["ports"],"commands":["ports"],"capability_color":null},{"id":"fuzz","name":"Fuzz","description":"Discover directories and parameters from wordlists; fold catch-all responses.","description_words":9,"replaces":["ffuf","arjun"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M4 5h8 M4 11h8 M4 17h8 M4 23h8 M16 4v20 M16 14h8 M21 11l3 3-3 3","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Wordlist through a gate","collectors":["dirs","params"],"commands":["dirs","fuzz","params"],"capability_color":null},{"id":"shots","name":"Shots","description":"Take screenshots of web services and group visually similar images.","description_words":10,"replaces":["gowitness"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M4 10V4h6 M18 4h6v6 M24 18v6h-6 M10 24H4v-6 M14 9l5 5-5 5-5-5Z","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Capture frame","collectors":["shots"],"commands":["shots","gallery"],"capability_color":null},{"id":"roles","name":"Roles","description":"Replay requests across signed-in roles to compare read and write access.","description_words":11,"replaces":["manual work","Autorize"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M6 4h5l2 2v5l-2 2H6l-2-2V6Z M17 15h5l2 2v5l-2 2h-5l-2-2v-5Z M15 7h5v5 M13 21H8v-5","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Cross-role replay","commands":["roles","report"],"capability_color":null,"stages":["the roles stages"]},{"id":"verify","name":"Verify","description":"Match versions to advisories and label results by available evidence.","description_words":10,"replaces":["manual work"],"replacement_scope":"Only the capability described; no claim of full feature parity.","glyph":{"viewBox":"0 0 28 28","path":"M17 4H8L4 8v9l4 4h9l4-4V8Z M20 20l5 5 M9 12h7 M9 16h4","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"square","strokeLinejoin":"miter"},"concept":"Inspect evidence, without a proof checkmark","commands":["run -advisories","run -verify"],"capability_color":null,"stages":["advisories","verify"]}];
const CAP_PATHS = {"sources":"M4 5h4v4H4Z M4 19h4v4H4Z M20 12h4v4h-4Z M8 7h5l5 7h2 M8 21h5l5-7","names":"M11 3h6v6h-6Z M4 19h6v6H4Z M18 19h6v6h-6Z M14 9v5 M7 19v-5h14v5","web":"M4 4h16l4 4v16H4Z M4 10h20 M9 7h1 M8 17h4l3-3h5 M12 17l3 4h5","ports":"M4 5h20v7H4Z M4 17h20v7H4Z M9 8v1 M19 8v1 M9 20v1 M19 20v1","fuzz":"M4 5h8 M4 11h8 M4 17h8 M4 23h8 M16 4v20 M16 14h8 M21 11l3 3-3 3","shots":"M4 10V4h6 M18 4h6v6 M24 18v6h-6 M10 24H4v-6 M14 9l5 5-5 5-5-5Z","roles":"M6 4h5l2 2v5l-2 2H6l-2-2V6Z M17 15h5l2 2v5l-2 2h-5l-2-2v-5Z M15 7h5v5 M13 21H8v-5","verify":"M17 4H8L4 8v9l4 4h9l4-4V8Z M20 20l5 5 M9 12h7 M9 16h4"};
const COLLECTORS = [{"name":"azhaq-asn","kind":"passive","inputs":["ASN"],"outputs":["prefixes"]},{"name":"azhaq-crawl","kind":"touch","after":"azhaq-http","inputs":["URL"],"outputs":["url"]},{"name":"azhaq-dirs","kind":"active","flag":"dirs","after":"azhaq-http","inputs":["URL"],"outputs":["url"]},{"name":"azhaq-dns","kind":"passive","inputs":["Hostname"],"outputs":["dns"],"batch":true},{"name":"azhaq-dns-brute","kind":"active","flag":"dns-brute","inputs":["Domain"],"outputs":["subdomains"]},{"name":"azhaq-graphql","kind":"touch","after":"azhaq-http","inputs":["URL"],"outputs":["graphql"]},{"name":"azhaq-graphql-schema","kind":"active","flag":"graphql","after":"azhaq-graphql","inputs":["URL"],"outputs":["graphql"]},{"name":"azhaq-http","kind":"touch","after":"azhaq-dns","inputs":["URL","Hostname","IPAddress"],"outputs":["application"]},{"name":"azhaq-js","kind":"touch","after":"azhaq-http","inputs":["URL"],"outputs":["url"]},{"name":"azhaq-openapi","kind":"touch","after":"azhaq-http","inputs":["URL"],"outputs":["api","url"]},{"name":"azhaq-params","kind":"active","flag":"params","after":"azhaq-http","inputs":["URL"],"outputs":["params"]},{"name":"azhaq-paths","kind":"touch","after":"azhaq-http","inputs":["URL"],"outputs":["url"]},{"name":"azhaq-permute","kind":"active","flag":"permute","after":"azhaq-dns","inputs":["Hostname"],"outputs":["subdomains"]},{"name":"azhaq-ports","kind":"active","flag":"ports","after":"azhaq-dns","inputs":["Hostname","IPAddress","Prefix"],"outputs":["ports"]},{"name":"azhaq-prefix","kind":"passive","inputs":["Prefix"],"outputs":["addresses"]},{"name":"azhaq-ptr","kind":"passive","inputs":["IPAddress"],"outputs":["ptr"],"batch":true},{"name":"azhaq-rdap","kind":"passive","inputs":["Domain","Organization"],"outputs":["rdap","organization","domain"]},{"name":"azhaq-render","kind":"touch","after":"azhaq-http","inputs":["URL"],"outputs":["url"]},{"name":"azhaq-search","kind":"passive","inputs":["Domain"],"outputs":["services"]},{"name":"azhaq-shots","kind":"touch","after":"azhaq-http","inputs":["URL","Hostname","IPAddress"],"outputs":["screenshot"]},{"name":"azhaq-subdomains","kind":"passive","inputs":["Domain"],"outputs":["subdomains"]},{"name":"azhaq-tls","kind":"touch","after":"azhaq-dns","inputs":["Hostname","IPAddress"],"outputs":["certificate"]},{"name":"azhaq-urls","kind":"passive","inputs":["Domain"],"outputs":["url"]}];
const COLLECTOR_CAP = {"azhaq-subdomains":"sources","azhaq-urls":"sources","azhaq-rdap":"sources","azhaq-search":"sources","azhaq-dns":"names","azhaq-dns-brute":"names","azhaq-permute":"names","azhaq-asn":"names","azhaq-prefix":"names","azhaq-ptr":"names","azhaq-http":"web","azhaq-paths":"web","azhaq-crawl":"web","azhaq-js":"web","azhaq-render":"web","azhaq-tls":"web","azhaq-openapi":"web","azhaq-graphql":"web","azhaq-graphql-schema":"web","azhaq-ports":"ports","azhaq-dirs":"fuzz","azhaq-params":"fuzz","azhaq-shots":"shots"};
let focusCapability = null;
function collectorFacts(name) {
  const summary = current?.run?.record?.summary || {};
  const entries = (summary.cost?.stages || []).flatMap(stage => (stage.collectors || []).filter(c => c.collector === name).map(c => ({stage: stage.stage, ...c})));
  const failures = (summary.failed || []).filter(f => f.collector === name);
  const ledger = current?.run?.ledger || {};
  // API variants may expose lines as entries or pre-aggregated by_collector.
  const lines = Array.isArray(ledger.entries) ? ledger.entries.filter(e => e.collector === name).length : null;
  const aggregate = ledger.by_collector?.[name];
  const ledgerCount = typeof aggregate === 'number' ? aggregate : typeof aggregate?.count === 'number' ? aggregate.count : lines;
  const used = entries.some(e => Object.hasOwn(e, 'actual') && e.actual != null) || (ledgerCount != null && ledgerCount > 0);
  return {entries, failures, ledgerCount, used};
}
function appendCollectorFacts(body, name) {
  const facts = collectorFacts(name);
  const units = {requests: 'requests', dns_queries: 'DNS queries', source_queries: 'source queries', connects: 'connections'};
  let hasRequests = false;
  for (const entry of facts.entries) {
    for (const [key, unit] of Object.entries(units)) {
      const actual = entry.actual?.[key], estimate = entry.estimate?.[key];
      if (typeof actual !== 'number' && typeof estimate !== 'number') continue;
      if (typeof actual === 'number' && actual > 0) hasRequests = true;
      let sentence = typeof actual === 'number' ? `${key === 'requests' ? 'Sent' : 'Recorded'} ${actual} ${unit}` : `${unit}: not recorded`;
      if (typeof estimate === 'number') sentence += ` (estimated ${estimate})`;
      if (entry.stage) sentence += ` · ${entry.stage}`;
      body.append(el('p', null, sentence));
    }
  }
  if (!hasRequests && !(facts.ledgerCount > 0)) body.append(el('p', 'muted', 'No request recorded for this collector in this run.'));
  if (facts.ledgerCount != null && facts.ledgerCount > 0) body.append(el('p', null, `${facts.ledgerCount} ledger lines recorded for this collector`));
  for (const failure of facts.failures) {
    const reason = String(failure.error || 'failure');
    const count = typeof failure.count === 'number' ? failure.count : null;
    body.append(el('p', null, count == null ? reason : `${count} ${reason === 'timeout' ? (count === 1 ? 'timeout' : 'timeouts') : reason}`));
  }
}
function drawExecution() {
  const d=window.devicePixelRatio||1, r=canvas.getBoundingClientRect();
  ctx.setTransform(d,0,0,d,0,0);ctx.clearRect(0,0,r.width,r.height);executionNodes=[];if(!current)return;
  const cx=r.width/2, cy=r.height/2, rx=Math.max(40,Math.min(300,(r.width-150)/2)), ry=Math.max(40,Math.min(180,(r.height-130)/2));
  const focused=CAPABILITIES.find(c=>c.id===focusCapability), caps=focused?[focused]:CAPABILITIES;
  const nodes=[];
  if(focused) {
    nodes.push({id:'cap:'+focused.id,key:focused.name,type:'Capability',execution:true,capability:focused,x:cx,y:cy,radius:31});
    const own=(focused.collectors||[]).map(name=>'azhaq-'+name), external=[];
    for(const name of own){const parent=COLLECTORS.find(c=>c.name===name)?.after;if(parent&&!own.includes(parent)&&!external.includes(parent))external.push(parent)}
    [...own,...external].forEach((name,i,all)=>{const a=-Math.PI/2+i*Math.PI*2/all.length;nodes.push({id:'collector:'+name,key:name,type:'Collector',execution:true,collector:name,capability:focused,external:!own.includes(name),x:cx+rx*Math.cos(a),y:cy+ry*Math.sin(a),radius:24})});
  } else {
    ctx.strokeStyle=css('--line');ctx.lineWidth=1;ctx.beginPath();ctx.ellipse(cx,cy,rx,ry,0,0,Math.PI*2);ctx.stroke();
    ctx.fillStyle=css('--fg');ctx.font='600 22px Arial, sans-serif';ctx.textAlign='center';ctx.fillText('azhaq',cx,cy+8);
    caps.forEach((cap,i)=>{const a=-Math.PI/2+i*Math.PI/4;nodes.push({id:'cap:'+cap.id,key:cap.name,type:'Capability',execution:true,capability:cap,x:cx+rx*Math.cos(a),y:cy+ry*Math.sin(a),radius:28})});
  }
  const nodeMap=new Map(nodes.filter(n=>n.collector).map(n=>[n.collector,n]));
  if(focused)for(const n of nodes.filter(n=>n.collector)) {
    const meta=COLLECTORS.find(c=>c.name===n.collector), parent=meta?.after&&nodeMap.get(meta.after);
    if(!parent)continue;
    const dx=n.x-parent.x,dy=n.y-parent.y,len=Math.hypot(dx,dy)||1,ux=dx/len,uy=dy/len,ex=n.x-ux*n.radius,ey=n.y-uy*n.radius;ctx.strokeStyle=css('--muted');ctx.fillStyle=css('--muted');ctx.globalAlpha=.45;ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(parent.x+ux*parent.radius,parent.y+uy*parent.radius);ctx.lineTo(ex,ey);ctx.stroke();ctx.beginPath();ctx.moveTo(ex,ey);ctx.lineTo(ex-ux*7-uy*3,ey-uy*7+ux*3);ctx.lineTo(ex-ux*7+uy*3,ey-uy*7-ux*3);ctx.closePath();ctx.fill();ctx.globalAlpha=1;
  }
  ctx.textAlign='center';
  for(const n of nodes) {
    const active=selectedGraph===n.id, used=n.collector?collectorFacts(n.collector).used:(n.capability.collectors||[]).some(name=>collectorFacts('azhaq-'+name).used);
    n.used=used;executionNodes.push(n);ctx.fillStyle=css('--card');ctx.strokeStyle=active?css('--accent'):used?css('--fg'):css('--line');ctx.lineWidth=active?2:1;
    ctx.beginPath();ctx.roundRect(n.x-n.radius,n.y-n.radius,n.radius*2,n.radius*2,6);ctx.fill();ctx.stroke();
    if(used){ctx.strokeStyle=css('--fg');ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(n.x-n.radius,n.y-8);ctx.lineTo(n.x-n.radius,n.y+8);ctx.stroke()}
    if(n.collector){const meta=COLLECTORS.find(c=>c.name===n.collector);ctx.fillStyle=used?css('--fg'):css('--muted');ctx.font='12px Arial,sans-serif';ctx.fillText(meta?.kind==='passive'?'○':meta?.kind==='touch'?'●':'◇',n.x,n.y+4)}
    else{ctx.save();ctx.translate(n.x-14,n.y-14);ctx.strokeStyle=used?css('--fg'):css('--muted');ctx.lineWidth=2;ctx.stroke(new Path2D(CAP_PATHS[n.capability.id]));ctx.restore()}
    ctx.fillStyle=used?css('--fg'):css('--muted');ctx.font='12px Arial,sans-serif';ctx.fillText(n.collector?n.key.replace('azhaq-','')+(n.external?' · external':''):n.key,n.x,n.y+n.radius+16);
  }
  ctx.textAlign='start';
}
function showExecution(node) {
  selectedGraph=node.id;
  if(!node.collector) focusCapability=focusCapability===node.capability.id?null:node.capability.id;
  $('execution-back').hidden=!focusCapability;
  $('panel').hidden=false;$('ptitle').textContent=node.key;
  const body=$('pbody');body.replaceChildren();
  if(node.collector) {
    const meta=COLLECTORS.find(c=>c.name===node.collector)||{};
    body.append(el('p',null,'Kind: '+(meta.kind||'not recorded')),el('p',null,'Inputs: '+(meta.inputs?.join(', ')||'not recorded')),el('p',null,'Outputs: '+(meta.outputs?.join(', ')||'not recorded')),el('p',null,'Declared after: '+(meta.after||'none')));
    appendCollectorFacts(body,node.collector);
    body.append(el('p','muted','Attempt reason, actual inputs, times and fed-by: not recorded.'));
  } else {
    const names=node.capability.collectors||[];
    if(!names.length) body.append(el('p','muted','Stage details: not recorded.'));
    for(const short of names) {const full='azhaq-'+short,meta=COLLECTORS.find(c=>c.name===full)||{},item=el('div','obs');item.append(el('strong',null,full),el('p','muted',(meta.kind||'not recorded')+' · '+(collectorFacts(full).used?'Used':'Available')));appendCollectorFacts(item,full);body.append(item)}
  }
  // Grid tracks change when the panel opens; wait until layout has settled.
  requestAnimationFrame(resize);
}
$('execution').addEventListener('click',()=>{graphMode='execution';focusCapability=null;selectedGraph=null;for(const id of ['search','fit','unfold','legend'])$(id).hidden=true;$('execution-back').hidden=true;$('execution').setAttribute('aria-pressed','true');$('results').setAttribute('aria-pressed','false');closePanel();draw()});
$('execution-back').addEventListener('click',()=>{focusCapability=null;selectedGraph=null;$('execution-back').hidden=true;closePanel();draw()});
$('results').addEventListener('click',()=>{graphMode='results';selectedGraph=null;for(const id of ['search','fit','unfold','legend'])$(id).hidden=false;$('execution-back').hidden=true;$('execution').setAttribute('aria-pressed','false');$('results').setAttribute('aria-pressed','true');closePanel();draw()});
canvas.addEventListener('keydown',event=>{if(!current)return;const nodes=graphMode==='execution'?executionNodes:[...current.model.nodes.values()];if(!nodes.length)return;const currentNode=nodes.find(n=>n.id===selectedGraph);let next=null;if(['ArrowRight','ArrowLeft','ArrowUp','ArrowDown'].includes(event.key)){const vector={ArrowRight:[1,0],ArrowLeft:[-1,0],ArrowDown:[0,1],ArrowUp:[0,-1]}[event.key];if(!currentNode)next=nodes[0];else{const options=nodes.filter(n=>n.id!==currentNode.id).map(n=>{const dx=n.x-currentNode.x,dy=n.y-currentNode.y,forward=dx*vector[0]+dy*vector[1],side=Math.abs(dx*vector[1]-dy*vector[0]);return {n,forward,score:forward+2*side}}).filter(v=>v.forward>0).sort((a,b)=>a.score-b.score);next=options[0]?.n}event.preventDefault();if(next){selectedGraph=next.id;hover=next.id;if(graphMode==='results'){const r=canvas.getBoundingClientRect();view.x=r.width/2-(next.x+NODE_W/2)*view.s;view.y=r.height/2-(next.y+NODE_H/2)*view.s} $('graph-focus').textContent=next.key;draw()}}else if((event.key==='Enter'||event.key===' ')&&currentNode){event.preventDefault();openNode(currentNode)}});

new ResizeObserver(() => resize()).observe(canvas.parentElement);
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
  runs.setAttribute('aria-expanded', String(!matchMedia('(max-width:720px)').matches));
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
