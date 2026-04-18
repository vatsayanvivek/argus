// ARGUS dashboard client. Single-file vanilla JS — no framework, no build.
// Works entirely against the local server's JSON API. Nothing phones home.

const state = {
  scans: [],
  currentScan: null,
  findings: [],
  chains: [],
  rules: [],
};

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

const api = {
  scans: () => fetch('/api/scans').then(r => r.json()),
  scan: (id) => fetch(`/api/scan/${encodeURIComponent(id)}`).then(r => r.json()),
  chains: () => fetch('/api/chains').then(r => r.json()),
  rules: () => fetch('/api/rules').then(r => r.json()),
  diff: (a, b) => fetch(`/api/diff/${encodeURIComponent(a)}/${encodeURIComponent(b)}`).then(r => r.json()),
  scanStatus: () => fetch('/api/scan-status').then(r => r.json()),
  triggerScan: (sub, tenant) => fetch('/api/trigger-scan', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({subscription: sub, tenant: tenant})
  }).then(r => r.json()),
};

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

const sevRank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

function severityPill(sev) {
  return `<span class="severity-tag ${sev||''}">${sev||''}</span>`;
}

function formatTime(t) {
  if (!t) return '—';
  const d = new Date(t);
  return d.toLocaleString();
}

function toast(msg, ms=2500) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add('hidden'), ms);
}

function el(tag, attrs, children) {
  const n = document.createElement(tag);
  if (attrs) {
    for (const k of Object.keys(attrs)) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'text') n.textContent = attrs[k];
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), attrs[k]);
      else n.setAttribute(k, attrs[k]);
    }
  }
  if (children) children.forEach(c => n.appendChild(c));
  return n;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

function showView(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.view === name));
  document.querySelectorAll('.view').forEach(v => v.classList.toggle('active', v.id === `view-${name}`));
  if (name === 'graph' && state.currentScan) renderGraph();
  if (name === 'compliance' && state.currentScan) renderCompliance();
}
document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => showView(t.dataset.view)));

// ---------------------------------------------------------------------------
// Scan picker
// ---------------------------------------------------------------------------

async function loadScans() {
  state.scans = await api.scans();
  const picker = document.getElementById('scan-picker');
  picker.innerHTML = '';
  if (state.scans.length === 0) {
    const opt = el('option', {value: ''});
    opt.textContent = 'No scans yet — run `argus scan --output json`';
    picker.appendChild(opt);
    renderOverview(null);
    renderHistory([]);
    renderDriftPickers([]);
    return;
  }
  state.scans.forEach(s => {
    const opt = el('option', {value: s.id});
    const ts = formatTime(s.scan_time);
    opt.textContent = `${ts} · ${s.subscription_id||'—'} · ${s.critical}C/${s.high}H`;
    picker.appendChild(opt);
  });
  picker.value = state.scans[0].id;
  await loadCurrentScan(picker.value);
  renderHistory(state.scans);
  renderDriftPickers(state.scans);
}

async function loadCurrentScan(id) {
  if (!id) { state.currentScan = null; return; }
  try {
    const scan = await api.scan(id);
    state.currentScan = scan;
    state.findings = scan.findings || [];
    state.chains = scan.chains || [];
    renderOverview(scan);
    renderFindings();
    renderChains();
    if (document.getElementById('view-graph').classList.contains('active')) renderGraph();
    if (document.getElementById('view-compliance').classList.contains('active')) renderCompliance();
  } catch (e) {
    toast('Failed to load scan: ' + e.message);
  }
}

document.getElementById('scan-picker').addEventListener('change', (e) => loadCurrentScan(e.target.value));

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

function renderOverview(scan) {
  const root = document.getElementById('overview-summary');
  root.innerHTML = '';
  if (!scan) {
    const empty = el('div', {class: 'empty-state'});
    empty.innerHTML = '<div class="icon">○</div><div><b>No scan loaded</b></div><div>Click <b>Run scan</b> above, or point <code>--scan-dir</code> at your argus output directory.</div>';
    root.parentElement.insertBefore(empty, root);
    document.getElementById('overview-critical').innerHTML = '';
    document.getElementById('overview-chains').innerHTML = '';
    return;
  }
  const findings = scan.findings || [];
  const chains = scan.chains || [];
  const buckets = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  findings.forEach(f => { if (buckets[f.severity] !== undefined) buckets[f.severity]++; });
  const cards = [
    ['critical', 'Critical findings', buckets.CRITICAL, 'Break chains first'],
    ['high', 'High findings', buckets.HIGH, 'Investigate within 48h'],
    ['medium', 'Medium findings', buckets.MEDIUM, 'Next sprint'],
    ['low', 'Low findings', buckets.LOW, 'Backlog'],
    ['chains', 'Active attack chains', chains.length, chains.length ? 'Click graph tab for the visual' : 'No chains triggered'],
  ];
  cards.forEach(([cls, label, value, hint]) => {
    const c = el('div', {class: `summary-card ${cls}`});
    c.appendChild(el('div', {class: 'label', text: label}));
    c.appendChild(el('div', {class: 'value', text: String(value)}));
    c.appendChild(el('div', {class: 'hint', text: hint}));
    root.appendChild(c);
  });

  renderSeverityDonut(buckets);

  const crit = findings.filter(f => f.severity === 'CRITICAL').slice(0, 10);
  const critRoot = document.getElementById('overview-critical');
  critRoot.innerHTML = '';
  if (crit.length === 0) {
    const empty = el('div', {class: 'empty-state'});
    empty.innerHTML = '<div class="icon">✓</div><div><b>No critical findings.</b></div><div>Nice work — keep validating with scheduled scans.</div>';
    critRoot.appendChild(empty);
  } else {
    const table = el('table');
    table.innerHTML = '<thead><tr><th>Severity</th><th>Rule</th><th>Resource</th><th>Title</th></tr></thead>';
    const tbody = el('tbody');
    crit.forEach(f => {
      const tr = el('tr');
      tr.innerHTML = `<td>${severityPill(f.severity)}</td><td>${f.id}</td><td>${f.resource_name||f.resource_id}</td><td>${f.title||''}</td>`;
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    critRoot.appendChild(table);
  }

  const chainsRoot = document.getElementById('overview-chains');
  chainsRoot.innerHTML = '';
  if (chains.length === 0) {
    const empty = el('div', {class: 'empty-state'});
    empty.innerHTML = '<div class="icon">—</div><div><b>No attack chains triggered.</b></div><div>Individual findings exist but none of ARGUS\'s 200 chain patterns fire.</div>';
    chainsRoot.appendChild(empty);
  } else {
    chains.slice(0, 6).forEach(c => chainsRoot.appendChild(chainCard(c)));
  }
}

// Severity donut chart — rendered inline via SVG. No charting library.
function renderSeverityDonut(buckets) {
  // Ensure the donut row container exists (insert once, just before overview-critical).
  const anchor = document.getElementById('overview-critical');
  let row = document.getElementById('overview-donut-row');
  if (!row) {
    row = el('div', {class: 'donut-row', id: 'overview-donut-row'});
    anchor.parentElement.insertBefore(row, anchor);
  }
  row.innerHTML = '';

  const total = buckets.CRITICAL + buckets.HIGH + buckets.MEDIUM + buckets.LOW;
  const segs = [
    ['CRITICAL', buckets.CRITICAL, '#f43f5e'],
    ['HIGH',     buckets.HIGH,     '#fb923c'],
    ['MEDIUM',   buckets.MEDIUM,   '#facc15'],
    ['LOW',      buckets.LOW,      '#38bdf8'],
  ];

  const donut = el('div', {class: 'donut-card'});
  const chart = el('div', {class: 'chart'});
  const legend = el('div', {class: 'legend'});
  donut.appendChild(el('h3', {text: 'Severity distribution'}));
  donut.appendChild(chart);
  donut.appendChild(legend);

  // Build inline SVG donut
  const svgNS = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(svgNS, 'svg');
  svg.setAttribute('viewBox', '0 0 42 42');
  svg.setAttribute('width', '120');
  svg.setAttribute('height', '120');

  // Background ring
  const bg = document.createElementNS(svgNS, 'circle');
  bg.setAttribute('cx', '21'); bg.setAttribute('cy', '21'); bg.setAttribute('r', '15.915');
  bg.setAttribute('fill', 'transparent'); bg.setAttribute('stroke', 'rgba(255,255,255,0.05)');
  bg.setAttribute('stroke-width', '4');
  svg.appendChild(bg);

  let offset = 25;
  segs.forEach(([label, val, color]) => {
    if (val === 0 || total === 0) return;
    const pct = (val / total) * 100;
    const seg = document.createElementNS(svgNS, 'circle');
    seg.setAttribute('cx', '21'); seg.setAttribute('cy', '21'); seg.setAttribute('r', '15.915');
    seg.setAttribute('fill', 'transparent');
    seg.setAttribute('stroke', color);
    seg.setAttribute('stroke-width', '4');
    seg.setAttribute('stroke-dasharray', pct.toFixed(2) + ' ' + (100 - pct).toFixed(2));
    seg.setAttribute('stroke-dashoffset', offset.toFixed(2));
    seg.setAttribute('transform', 'rotate(-90 21 21)');
    svg.appendChild(seg);
    offset -= pct;
  });

  // Centre total text
  const t1 = document.createElementNS(svgNS, 'text');
  t1.setAttribute('x', '21'); t1.setAttribute('y', '20');
  t1.setAttribute('text-anchor', 'middle'); t1.setAttribute('fill', '#e8ecff');
  t1.setAttribute('font-size', '7'); t1.setAttribute('font-weight', '700');
  t1.textContent = String(total);
  svg.appendChild(t1);
  const t2 = document.createElementNS(svgNS, 'text');
  t2.setAttribute('x', '21'); t2.setAttribute('y', '26');
  t2.setAttribute('text-anchor', 'middle'); t2.setAttribute('fill', '#a0a7d4');
  t2.setAttribute('font-size', '3'); t2.setAttribute('letter-spacing', '0.3');
  t2.textContent = 'findings';
  svg.appendChild(t2);
  chart.appendChild(svg);

  segs.forEach(([label, val, color]) => {
    const row = el('div', {class: 'legend-row'});
    const left = el('span', {class: 'legend-label'});
    const dot = el('span', {class: 'legend-dot'});
    dot.style.background = color;
    left.appendChild(dot);
    left.appendChild(document.createTextNode(label));
    row.appendChild(left);
    row.appendChild(el('span', {text: String(val)}));
    legend.appendChild(row);
  });
  row.appendChild(donut);

  // Second card: chain severity split
  const donut2 = el('div', {class: 'donut-card'});
  donut2.innerHTML = '<h3>Top pillars by findings</h3>';
  const pillarStats = {};
  (state.findings || []).forEach(f => {
    const p = f.pillar || 'Other';
    pillarStats[p] = (pillarStats[p] || 0) + 1;
  });
  const pillarLegend = el('div', {class: 'legend'});
  const entries = Object.entries(pillarStats).sort((a, b) => b[1] - a[1]).slice(0, 6);
  if (entries.length === 0) {
    donut2.appendChild(el('div', {class: 'hint', text: 'No findings in this scan.'}));
  } else {
    entries.forEach(([name, n]) => {
      const r = el('div', {class: 'legend-row'});
      r.appendChild(el('span', {class: 'legend-label', text: name}));
      r.appendChild(el('span', {text: String(n)}));
      pillarLegend.appendChild(r);
    });
    donut2.appendChild(pillarLegend);
  }
  row.appendChild(donut2);
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

function renderFindings() {
  const search = document.getElementById('findings-search').value.toLowerCase();
  const sev = document.getElementById('findings-severity').value;
  const pillar = document.getElementById('findings-pillar').value;
  const tbody = document.querySelector('#findings-table tbody');
  tbody.innerHTML = '';

  const pillars = new Set();
  state.findings.forEach(f => { if (f.pillar) pillars.add(f.pillar); });
  const pillarSelect = document.getElementById('findings-pillar');
  if (pillarSelect.options.length <= 1) {
    [...pillars].sort().forEach(p => {
      const o = el('option', {value: p});
      o.textContent = p;
      pillarSelect.appendChild(o);
    });
  }

  const rows = state.findings.filter(f => {
    if (sev && f.severity !== sev) return false;
    if (pillar && f.pillar !== pillar) return false;
    if (!search) return true;
    const hay = `${f.id} ${f.title} ${f.resource_id} ${f.resource_name} ${f.detail}`.toLowerCase();
    return hay.includes(search);
  });
  rows.sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  rows.slice(0, 500).forEach(f => {
    const tr = el('tr');
    tr.innerHTML = `<td>${severityPill(f.severity)}</td><td>${f.id}</td><td>${f.resource_name||f.resource_id||'—'}</td><td>${f.pillar||'—'}</td><td>${f.title||''}</td>`;
    tbody.appendChild(tr);
  });
}
['findings-search', 'findings-severity', 'findings-pillar'].forEach(id => {
  document.getElementById(id).addEventListener('input', renderFindings);
});

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

function chainCard(c) {
  const n = el('div', {class: 'chain-card'});
  n.appendChild(el('h3', {text: `${c.id} · ${c.title||''}`}));
  const meta = el('div', {class: 'meta'});
  meta.innerHTML = `${severityPill(c.severity)} · ${c.trigger_logic||''} · ${(c.trigger_findings||[]).length} triggers`;
  n.appendChild(meta);
  n.addEventListener('click', () => showChainDetail(c));
  return n;
}

function renderChains() {
  const root = document.getElementById('chains-list');
  root.innerHTML = '';
  if (state.chains.length === 0) {
    root.appendChild(el('p', {class: 'hint', text: 'No chains triggered in this scan.'}));
    return;
  }
  const sorted = [...state.chains].sort((a, b) => (sevRank[a.severity] ?? 9) - (sevRank[b.severity] ?? 9));
  sorted.forEach(c => root.appendChild(chainCard(c)));
}

function showChainDetail(c) {
  const dlg = document.getElementById('chain-dialog');
  const root = document.getElementById('chain-dialog-content');
  root.innerHTML = '';
  root.appendChild(el('h2', {text: `${c.id} — ${c.title||''}`}));
  const meta = el('p');
  meta.innerHTML = `${severityPill(c.severity)} · ${c.likelihood||'—'} likelihood · ${c.trigger_logic||''}`;
  root.appendChild(meta);
  if (c.narrative) {
    root.appendChild(el('h3', {text: 'Why this chain matters'}));
    root.appendChild(el('p', {text: c.narrative}));
  }
  if (c.steps && c.steps.length) {
    root.appendChild(el('h3', {text: 'Attack walkthrough'}));
    c.steps.forEach(s => {
      const d = el('div', {class: 'chain-card'});
      d.innerHTML = `<b>Step ${s.number}. ${s.action||''}</b>
        <div class="meta">Actor: ${s.actor||'—'} · MITRE: ${s.technique||'—'} · Enabled by: ${s.enabled_by||'—'}</div>
        <div>${s.technical||''}</div>
        <div class="meta">Gain: ${s.gain||'—'}</div>`;
      root.appendChild(d);
    });
  }
  if (c.blast_radius) {
    root.appendChild(el('h3', {text: 'Blast radius'}));
    const br = c.blast_radius;
    const tbl = el('table');
    tbl.innerHTML = `
      <tbody>
        <tr><th>Initial access</th><td>${br.initial_access||'—'}</td></tr>
        <tr><th>Lateral movement</th><td>${br.lateral_movement||'—'}</td></tr>
        <tr><th>Max privilege</th><td>${br.max_privilege||'—'}</td></tr>
        <tr><th>Data at risk</th><td>${(br.data_at_risk||[]).join(', ')||'—'}</td></tr>
        <tr><th>Services at risk</th><td>${(br.services_at_risk||[]).join(', ')||'—'}</td></tr>
      </tbody>`;
    root.appendChild(tbl);
  }
  dlg.showModal();
}

// ---------------------------------------------------------------------------
// Attack graph (Cytoscape.js)
// ---------------------------------------------------------------------------

let graphCy = null;
function renderGraph() {
  if (!state.currentScan || !state.chains.length) {
    document.getElementById('graph-canvas').innerHTML = '<p class="hint" style="padding:20px">No chains in this scan — nothing to graph.</p>';
    return;
  }
  const elements = [];
  const addedNodes = new Set();
  state.chains.forEach(chain => {
    const chainId = chain.id;
    if (!addedNodes.has(chainId)) {
      elements.push({ data: { id: chainId, label: chain.title||chain.id, kind: 'chain', severity: chain.severity } });
      addedNodes.add(chainId);
    }
    (chain.trigger_findings||[]).forEach(rid => {
      if (!addedNodes.has(rid)) {
        elements.push({ data: { id: rid, label: rid, kind: 'rule' } });
        addedNodes.add(rid);
      }
      elements.push({ data: { id: `${chainId}->${rid}`, source: chainId, target: rid } });
    });
  });
  if (graphCy) graphCy.destroy();
  graphCy = cytoscape({
    container: document.getElementById('graph-canvas'),
    elements: elements,
    style: [
      { selector: 'node', style: {
        'background-color': '#6366f1', 'label': 'data(label)', 'color': '#fff',
        'font-size': 9, 'text-valign': 'center', 'text-halign': 'center',
        'width': 30, 'height': 30,
      }},
      { selector: 'node[kind="chain"]', style: {
        'background-color': '#ec4899', 'shape': 'round-rectangle',
        'width': 120, 'height': 40, 'font-size': 11,
      }},
      { selector: 'node[severity="CRITICAL"]', style: { 'background-color': '#f43f5e' } },
      { selector: 'node[severity="HIGH"]', style: { 'background-color': '#fb923c' } },
      { selector: 'edge', style: {
        'width': 1.5, 'line-color': '#2a3158',
        'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
        'target-arrow-color': '#2a3158',
      }},
    ],
    layout: { name: 'cose', padding: 30, animate: false },
  });
  graphCy.on('tap', 'node', (evt) => {
    const n = evt.target.data();
    const panel = document.getElementById('graph-detail');
    panel.innerHTML = `<h3>${n.id}</h3><p>Kind: ${n.kind}</p>`;
    if (n.kind === 'chain') {
      const chain = state.chains.find(c => c.id === n.id);
      if (chain) {
        panel.innerHTML += `<p>${chain.narrative||''}</p>`;
      }
    } else {
      const f = state.findings.find(ff => ff.id === n.id);
      if (f) panel.innerHTML += `<p>${f.title||''}</p><p>${f.detail||''}</p>`;
    }
  });
}

// ---------------------------------------------------------------------------
// Compliance
// ---------------------------------------------------------------------------

function renderCompliance() {
  const root = document.getElementById('compliance-packs');
  root.innerHTML = '';
  const byFramework = {};
  (state.findings||[]).forEach(f => {
    const m = f.compliance_mappings || {};
    for (const fw of Object.keys(m)) {
      if (!byFramework[fw]) byFramework[fw] = { failing: 0, controls: new Set() };
      byFramework[fw].failing += 1;
      (m[fw]||[]).forEach(c => byFramework[fw].controls.add(c));
    }
  });
  if (Object.keys(byFramework).length === 0) {
    root.appendChild(el('p', {class: 'hint', text: 'No compliance mappings in this scan. Run with --compliance soc2 (or similar) for a targeted report.'}));
    return;
  }
  for (const fw of Object.keys(byFramework).sort()) {
    const pack = byFramework[fw];
    const card = el('div', {class: 'compliance-pack'});
    card.innerHTML = `
      <h3>${fw.toUpperCase()}</h3>
      <p class="meta">${pack.failing} finding(s) across ${pack.controls.size} control(s)</p>
    `;
    root.appendChild(card);
  }
}

// ---------------------------------------------------------------------------
// Drift
// ---------------------------------------------------------------------------

function renderDriftPickers(scans) {
  ['drift-from', 'drift-to'].forEach(id => {
    const sel = document.getElementById(id);
    sel.innerHTML = '';
    scans.forEach(s => {
      const opt = el('option', {value: s.id});
      opt.textContent = `${formatTime(s.scan_time)} · ${s.subscription_id||'—'}`;
      sel.appendChild(opt);
    });
  });
  if (scans.length >= 2) {
    document.getElementById('drift-from').value = scans[1].id;
    document.getElementById('drift-to').value = scans[0].id;
  }
}

document.getElementById('drift-run-btn').addEventListener('click', async () => {
  const from = document.getElementById('drift-from').value;
  const to = document.getElementById('drift-to').value;
  if (!from || !to) { toast('Pick two scans'); return; }
  const res = await api.diff(from, to);
  const root = document.getElementById('drift-result');
  root.innerHTML = `
    <h2>Added findings (${res.added_findings.length})</h2>
    <ul class="diff-list diff-added">${res.added_findings.map(f => `<li>${severityPill(f.severity)} ${f.id} · ${f.resource_name||f.resource_id}</li>`).join('')}</ul>
    <h2>Resolved findings (${res.resolved_findings.length})</h2>
    <ul class="diff-list diff-resolved">${res.resolved_findings.map(f => `<li>${severityPill(f.severity)} ${f.id} · ${f.resource_name||f.resource_id}</li>`).join('')}</ul>
    <h2>Chain changes</h2>
    <p>Added: ${res.added_chains.join(', ')||'(none)'}</p>
    <p>Resolved: ${res.resolved_chains.join(', ')||'(none)'}</p>
  `;
});

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

function renderHistory(scans) {
  const tbody = document.querySelector('#history-table tbody');
  tbody.innerHTML = '';
  scans.forEach(s => {
    const tr = el('tr');
    tr.innerHTML = `<td>${formatTime(s.scan_time)}</td><td>${s.subscription_id||'—'}</td><td>${s.critical}</td><td>${s.high}</td><td>${s.medium}</td><td>${s.low}</td><td>${s.chains_count}</td>`;
    tbody.appendChild(tr);
  });
}

// ---------------------------------------------------------------------------
// Trigger scan
// ---------------------------------------------------------------------------

document.getElementById('trigger-scan-btn').addEventListener('click', () => {
  document.getElementById('scan-dialog').showModal();
});
document.getElementById('scan-dialog-run').addEventListener('click', async () => {
  const sub = document.getElementById('scan-subscription').value.trim();
  const tenant = document.getElementById('scan-tenant').value.trim();
  if (!sub || !tenant) { toast('Both subscription and tenant are required'); return; }
  document.getElementById('scan-dialog').close();
  const r = await api.triggerScan(sub, tenant);
  if (r.error) { toast('Error: ' + r.error); return; }
  toast('Scan started in background');
  pollScanStatus();
});

async function pollScanStatus() {
  for (let i = 0; i < 600; i++) {
    await new Promise(r => setTimeout(r, 2000));
    const s = await api.scanStatus();
    if (!s.running) {
      toast(s.error ? 'Scan finished with errors: ' + s.error : 'Scan complete');
      await loadScans();
      return;
    }
  }
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

loadScans();
