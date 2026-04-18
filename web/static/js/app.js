'use strict';

// ── State ─────────────────────────────────────────────────────────────────
let lastDomain = '';
let lastResults = null;

// ── View switching ────────────────────────────────────────────────────────
function switchView(name) {
  document.querySelectorAll('.view').forEach(v => {
    v.style.display = 'none';
    v.classList.remove('active');
  });
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const view = document.getElementById(`view-${name}`);
  if (view) { view.style.display = 'block'; view.classList.add('active'); }
  const btn = document.querySelector(`[data-view="${name}"]`);
  if (btn) btn.classList.add('active');
}

// ── Domain checker ────────────────────────────────────────────────────────
function getDomain() {
  return document.getElementById('domainInput').value.trim();
}

function getCustomSelectors() {
  const v = document.getElementById('dkimSelector').value.trim();
  return v ? v.split(/[\s,;]+/).filter(Boolean) : [];
}

async function runAll() {
  const domain = getDomain();
  if (!domain) { flashInput(); return; }
  lastDomain = domain;

  showResultsSection();
  setProgress(5);
  setAllLoading();

  try {
    const data = await post('/check', { domain, dkim_selectors: getCustomSelectors() });
    lastResults = data;
    setProgress(100);

    renderScore(data.score);
    renderMX(data.mx);
    renderSPF(data.spf);
    renderDMARC(data.dmarc);
    renderDKIM(data.dkim);
    renderBIMI(data.bimi);
    renderBlacklist(data.blacklist);
    renderSMTP(data.smtp);

    document.getElementById('exportBtn').style.display = 'flex';
    setTimeout(() => hideProgress(), 600);
  } catch (e) {
    setProgress(0);
    showToast('Request failed: ' + (e.message || e), 'fail');
  }
}

async function runSingle(type) {
  const domain = getDomain();
  if (!domain) { flashInput(); return; }
  lastDomain = domain;

  showResultsSection();
  setCardLoading(type);
  setProgress(20);

  try {
    const data = await post(`/check/${type}`, { domain, dkim_selectors: getCustomSelectors() });
    setProgress(100);

    const renders = { mx: renderMX, spf: renderSPF, dmarc: renderDMARC, dkim: renderDKIM,
                      bimi: renderBIMI, blacklist: renderBlacklist, smtp: renderSMTP };
    if (renders[type]) renders[type](data);
    setTimeout(() => hideProgress(), 500);
  } catch (e) {
    setProgress(0);
    showToast('Request failed: ' + (e.message || e), 'fail');
  }
}

// ── PDF export ────────────────────────────────────────────────────────────
async function exportPDF() {
  const domain = lastDomain || getDomain();
  if (!domain) { flashInput(); return; }
  showToast('Generating PDF report…', 'info');
  try {
    const resp = await fetch('/report/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, dkim_selectors: getCustomSelectors() }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `mailcheck-${domain}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
    showToast('PDF downloaded', 'pass');
  } catch (e) {
    showToast('PDF failed: ' + e.message, 'fail');
  }
}

// ── Header analyzer ───────────────────────────────────────────────────────
async function runHeaderAnalysis() {
  const headers = document.getElementById('headerInput').value.trim();
  if (!headers) { showToast('Paste email headers first', 'warn'); return; }

  const resultsEl = document.getElementById('header-results');
  const cardsEl   = document.getElementById('header-cards');
  resultsEl.style.display = 'block';
  cardsEl.innerHTML = '<div class="check-card full-width"><div class="card-body"><div class="card-skeleton"></div></div></div>';
  setProgress(30);

  try {
    const data = await post('/check/headers', { headers });
    setProgress(100);
    renderHeaderResults(data);
    setTimeout(() => hideProgress(), 500);
  } catch (e) {
    setProgress(0);
    showToast('Analysis failed: ' + e.message, 'fail');
  }
}

// ── Renderers ─────────────────────────────────────────────────────────────

function renderScore(score) {
  if (!score) return;
  const grade = score.grade || '—';
  const gradeEl = document.getElementById('scoreGrade');
  gradeEl.textContent = grade;
  gradeEl.className = `score-grade grade-${grade}`;
  document.getElementById('scoreNumber').textContent = `${score.score}/100`;

  const issuesEl = document.getElementById('scoreIssues');
  issuesEl.innerHTML = '';
  (score.issues || []).forEach(i => {
    const li = document.createElement('li');
    li.className = 'score-issue';
    li.innerHTML = `<span class="issue-dot ${i.severity}"></span><span>${esc(i.text)}</span>`;
    issuesEl.appendChild(li);
  });
}

function renderMX(data) {
  const sev = data.status === 'ok' ? 'pass' : 'fail';
  setBadge('mx', sev, data.status === 'ok' ? 'Pass' : data.status);

  if (data.status !== 'ok' || !data.records?.length) {
    setBody('mx', stateHtml(data.status, data.error || 'No MX records found'));
    return;
  }

  let rows = data.records.map(r => `
    <tr>
      <td><span class="priority-badge">${r.priority}</span></td>
      <td><span class="host-name">${esc(r.host)}</span></td>
      <td><span class="ip-text">${esc(r.ip || '—')}</span></td>
      <td><span class="ptr-text">${esc(r.ptr || '—')}</span></td>
    </tr>`).join('');

  setBody('mx', `
    <table class="mx-table">
      <thead><tr>
        <th>Priority</th><th>Host</th><th>IP</th><th>PTR (rDNS)</th>
      </tr></thead>
      <tbody>${rows}</tbody>
    </table>`);
}

function renderSPF(data) {
  if (data.status === 'missing' || data.status === 'error') {
    setBadge('spf', data.status === 'missing' ? 'missing' : 'fail', data.status);
    setBody('spf', stateHtml(data.status, data.error || 'No SPF record found'));
    return;
  }

  const parsed = data.parsed || {};
  const warnings = parsed.warnings || [];
  const hasFail = warnings.some(w => w.includes('+all') || w.includes('Too many'));
  setBadge('spf', hasFail ? 'fail' : warnings.length ? 'warn' : 'pass',
           hasFail ? 'Fail' : warnings.length ? 'Warning' : 'Pass');

  const tags = [
    { k: 'Version', v: parsed.version || 'spf1' },
    { k: 'All', v: parsed.all_mechanism || 'none', hi: true },
    { k: 'Lookups', v: `${parsed.lookup_count || 0}/10`, hi: (parsed.lookup_count || 0) > 10 },
    { k: 'Includes', v: parsed.includes?.length || 0 },
    { k: 'IP4 ranges', v: parsed.ip4?.length || 0 },
    { k: 'IP6 ranges', v: parsed.ip6?.length || 0 },
  ];

  setBody('spf', `
    ${recordBlock(data.record)}
    <div class="tag-grid">${tags.map(t => tagPill(t.k, t.v, t.hi)).join('')}</div>
    ${findingsHtml(warnings.map(w => ({ severity: warnLevel(w), text: w })))}`);
}

function renderDMARC(data) {
  if (data.status === 'missing' || data.status === 'error') {
    setBadge('dmarc', data.status === 'missing' ? 'missing' : 'fail', data.status);
    setBody('dmarc', stateHtml(data.status, data.error || 'No DMARC record found'));
    return;
  }

  const parsed = data.parsed || {};
  const warnings = parsed.warnings || [];
  const policy = data.policy || parsed.p || 'none';
  const grade = policy === 'reject' ? 'pass' : policy === 'quarantine' ? 'warn' : 'warn';
  setBadge('dmarc', warnings.length ? grade : 'pass', policy === 'none' ? 'Policy: none' : `Policy: ${policy}`);

  const tags = [
    { k: 'Version', v: parsed.v || 'DMARC1' },
    { k: 'Policy', v: parsed.p || 'none', hi: true },
    { k: 'Sub Policy', v: parsed.sp || '(inherit)' },
    { k: 'DKIM Align', v: parsed.adkim === 's' ? 'strict' : 'relaxed' },
    { k: 'SPF Align', v: parsed.aspf === 's' ? 'strict' : 'relaxed' },
    { k: 'Pct', v: `${parsed.pct || 100}%` },
  ];

  const findings = warnings.map(w => ({ severity: 'warn', text: w }));
  if (parsed.rua) findings.unshift({ severity: 'pass', text: `Aggregate reports → ${parsed.rua}` });
  if (parsed.ruf) findings.unshift({ severity: 'pass', text: `Forensic reports → ${parsed.ruf}` });

  setBody('dmarc', `
    ${recordBlock(data.record)}
    <div class="tag-grid">${tags.map(t => tagPill(t.k, t.v, t.hi)).join('')}</div>
    ${findingsHtml(findings)}`);
}

function renderDKIM(data) {
  const found = data.found_selectors || [];
  if (!found.length) {
    setBadge('dkim', 'missing', 'Not Found');
    setBody('dkim', stateHtml('missing',
      `No DKIM records found — checked ${data.selectors_checked || 0} selectors automatically`));
    return;
  }
  setBadge('dkim', 'pass', `${found.length} selector${found.length > 1 ? 's' : ''} found`);

  const items = found.map(sel => {
    const p = sel.parsed || {};
    const warnings = (p.warnings || []).map(w => ({ severity: 'warn', text: w }));
    return `
      <div class="selector-item">
        <div class="selector-name">${esc(sel.selector)}</div>
        <div class="selector-fqdn">${esc(sel.fqdn)}</div>
        <div class="tag-grid">
          ${tagPill('Type', p.key_type || 'rsa')}
          ${tagPill('Status', p.key_revoked ? 'REVOKED' : 'Active', p.key_revoked)}
        </div>
        ${recordBlock(sel.record)}
        ${warnings.length ? findingsHtml(warnings) : ''}
      </div>`;
  }).join('');

  setBody('dkim', `
    <div class="finding info">
      <i class="ph ph-info"></i>
      Auto-detected: checked ${data.selectors_checked} selectors
    </div>
    <div style="margin-top:10px" class="selector-list">${items}</div>`);
}

function renderBIMI(data) {
  if (data.status === 'missing') {
    setBadge('bimi', 'missing', 'Not Configured');
    setBody('bimi', stateHtml('missing', 'No BIMI record found — requires DMARC policy of quarantine or reject'));
    return;
  }
  if (data.status === 'error') {
    setBadge('bimi', 'fail', 'Error');
    setBody('bimi', stateHtml('error', data.error));
    return;
  }

  const parsed = data.parsed || {};
  const warnings = parsed.warnings || [];
  setBadge('bimi', warnings.length ? 'warn' : 'pass', warnings.length ? 'Partial' : 'Pass');

  const logoUrl = data.logo_url;
  const vmcUrl = data.vmc_url;

  let logoHtml = '';
  if (logoUrl) {
    logoHtml = `<div class="bimi-wrap">
      <img class="bimi-logo" src="${esc(logoUrl)}" alt="BIMI logo" onerror="this.style.display='none'"/>
      <div style="flex:1">
        ${recordBlock(data.record)}
      </div>
    </div>`;
  }

  const tags = [
    { k: 'Selector', v: data.selector || 'default' },
    { k: 'Logo', v: logoUrl ? 'Present' : 'Missing', hi: !logoUrl },
    { k: 'VMC', v: vmcUrl ? 'Present' : 'Missing', hi: !vmcUrl },
  ];

  setBody('bimi', `
    ${logoHtml || recordBlock(data.record)}
    <div class="tag-grid">${tags.map(t => tagPill(t.k, t.v, t.hi)).join('')}</div>
    ${findingsHtml(warnings.map(w => ({ severity: 'warn', text: w })))}`);
}

function renderBlacklist(data) {
  if (data.status === 'error') {
    setBadge('blacklist', 'fail', 'Error');
    setBody('blacklist', stateHtml('error', data.error));
    return;
  }

  const listed = data.listed || [];
  const listCount = data.listed_count || 0;
  setBadge('blacklist', listCount > 0 ? 'fail' : 'pass',
           listCount > 0 ? `${listCount} Listed` : 'Clean');

  const ipLine = (data.ips_checked || []).map(ip => `<span class="ip-text" style="margin-right:8px">${esc(ip)}</span>`).join('');
  const summary = `<div class="bl-summary">
    Checked <strong>${data.lists_checked || 0}</strong> RBLs for ${ipLine}
    ${listCount === 0
      ? `<span class="finding pass" style="margin-top:8px;display:flex"><i class="ph ph-check-circle"></i> All clean</span>`
      : `<span style="color:var(--fail)"><strong>${listCount}</strong> listing(s) found</span>`}
  </div>`;

  const listed_html = listed.length
    ? `<div class="bl-listed">${listed.map(e => `
        <div class="bl-item">
          <div class="bl-name">${esc(e.name)}</div>
          <div class="bl-reason">${esc(e.reason || 'No reason provided')}</div>
          <div class="bl-code">Return code: ${esc((e.return_codes || []).join(', '))}</div>
        </div>`).join('')}</div>`
    : '';

  setBody('blacklist', summary + listed_html);
}

function renderSMTP(data) {
  if (data.status === 'error' && !data.results?.length) {
    setBadge('smtp', 'fail', 'Error');
    setBody('smtp', stateHtml('error', data.error || 'No SMTP results'));
    return;
  }

  const results = data.results || [];
  const anyConnected = results.some(r => r.connected);
  const anyTLS = results.some(r => r.tls_established);
  setBadge('smtp', !anyConnected ? 'fail' : !anyTLS ? 'warn' : 'pass',
           !anyConnected ? 'Unreachable' : !anyTLS ? 'No TLS' : 'Pass');

  const rows = results.map(r => {
    if (!r.connected) {
      return `<div class="smtp-row">
        <div class="smtp-host">${esc(r.host)}</div>
        <div class="smtp-meta">
          <span class="smtp-port">${r.port}</span>
          <span style="color:var(--fail)">${esc(r.error || 'Failed')}</span>
        </div>
      </div>`;
    }

    const tlsHtml = r.tls_established
      ? `<span class="tls-pill ok"><i class="ph ph-lock-simple"></i>${esc(r.tls_version || 'TLS')} · ${esc(r.cipher || '')}</span>`
      : (r.starttls_available === false
          ? `<span class="tls-pill none"><i class="ph ph-lock-simple-open"></i>No STARTTLS</span>`
          : `<span class="tls-pill none"><i class="ph ph-lock-simple-open"></i>Unencrypted</span>`);

    const features = (r.ehlo_features || []).slice(0, 8).join(', ');

    return `<div class="smtp-row">
      <div class="smtp-host">${esc(r.host)}</div>
      <div class="smtp-meta">
        <span class="smtp-port">${r.port}</span>
        <b>${r.latency_ms}ms</b>
        ${r.cert_cn ? ` · Cert: ${esc(r.cert_cn)}` : ''}
        ${r.cert_expiry ? ` · Expires: ${esc(r.cert_expiry)}` : ''}
      </div>
      ${tlsHtml}
      ${features ? `<div class="smtp-meta" style="margin-top:5px">EHLO: ${esc(features)}</div>` : ''}
      ${r.banner ? `<div class="smtp-banner">${esc(r.banner)}</div>` : ''}
    </div>`;
  }).join('');

  setBody('smtp', `<div class="smtp-grid">${rows}</div>`);
}

// ── Header analysis renderer ───────────────────────────────────────────────

function renderHeaderResults(data) {
  const cardsEl = document.getElementById('header-cards');
  if (data.status === 'error') {
    cardsEl.innerHTML = `<div class="check-card full-width">
      <div class="card-body">${stateHtml('error', data.error)}</div></div>`;
    return;
  }

  const s = data.summary || {};
  const auth = data.authentication || {};
  const anomalies = data.anomalies || [];
  const chain = data.received_chain || [];
  const alignment = data.alignment || {};

  // Build auth pills
  const protocols = ['spf', 'dkim', 'dmarc'];
  const authPills = protocols.flatMap(proto =>
    (auth[proto] || []).map(e => {
      const cls = e.result === 'pass' ? 'pass' : ['fail','hardfail','permerror'].includes(e.result) ? 'fail' : 'neutral';
      return `<span class="auth-pill ${cls}">${proto.toUpperCase()}: ${esc(e.result)}</span>`;
    })
  ).join('') || '<span class="auth-pill neutral">No auth results</span>';

  // Summary card
  const summaryRows = [
    ['From', s.from], ['To', s.to], ['Subject', s.subject],
    ['Date', s.date], ['Message-ID', s.message_id],
    ['Return-Path', s.return_path], ['Reply-To', s.reply_to || '—'],
    ['Delivery Time', data.delivery_time_seconds != null ? `${Math.round(data.delivery_time_seconds)}s` : '—'],
  ].filter(([, v]) => v).map(([k, v]) =>
    `<tr><td style="color:var(--text-dim);padding:5px 8px;white-space:nowrap;font-size:12px">${k}</td>
         <td style="padding:5px 8px;font-family:var(--mono);font-size:12px;word-break:break-all">${esc(v)}</td></tr>`
  ).join('');

  // Alignment
  const alignItems = [
    { label: 'From / Return-Path', val: alignment.from_return_path_match },
    { label: 'From / Reply-To', val: alignment.from_reply_to_match },
  ].filter(a => a.val !== null && a.val !== undefined).map(a =>
    `<div class="finding ${a.val ? 'pass' : 'warn'}">
       <i class="ph ${a.val ? 'ph-check-circle' : 'ph-warning'}"></i>
       ${a.label}: ${a.val ? 'Aligned' : 'Mismatch'}
     </div>`
  ).join('');

  // Received chain
  const hops = chain.map((h, i) => `
    <div class="hop" data-n="${i + 1}">
      <div class="hop-from">${esc(h.from || '?')} ${h.ip ? `[${esc(h.ip)}]` : ''}</div>
      ${h.by ? `<div class="hop-by">→ ${esc(h.by)} via ${esc(h.with || '?')}</div>` : ''}
      ${h.timestamp ? `<div class="hop-ts">${esc(h.timestamp)}</div>` : ''}
      ${h.tls
        ? '<span class="hop-tls"><i class="ph ph-lock-simple"></i>TLS</span>'
        : (h.from ? '<span class="hop-notls"><i class="ph ph-lock-simple-open"></i>No TLS</span>' : '')}
    </div>`).join('');

  // Anomalies
  const anomalyHtml = anomalies.length
    ? findingsHtml(anomalies.map(a => ({ severity: a.severity === 'fail' ? 'fail' : 'warn', text: a.message })))
    : `<div class="finding pass"><i class="ph ph-check-circle"></i>No anomalies detected</div>`;

  cardsEl.innerHTML = `
    <div class="check-card">
      <div class="card-header">
        <span class="card-icon"><i class="ph ph-envelope-open"></i></span>
        <span class="card-title">Message Summary</span>
      </div>
      <div class="card-body">
        <table style="width:100%;border-collapse:collapse">${summaryRows}</table>
      </div>
    </div>

    <div class="check-card">
      <div class="card-header">
        <span class="card-icon"><i class="ph ph-shield-check"></i></span>
        <span class="card-title">Authentication Results</span>
      </div>
      <div class="card-body">
        <div class="auth-results">${authPills}</div>
        <div class="section-label">Domain Alignment</div>
        <div class="findings">${alignItems || '<div class="finding info"><i class="ph ph-info"></i>No alignment data available</div>'}</div>
      </div>
    </div>

    <div class="check-card">
      <div class="card-header">
        <span class="card-icon"><i class="ph ph-warning"></i></span>
        <span class="card-title">Anomaly Detection</span>
      </div>
      <div class="card-body">${anomalyHtml}</div>
    </div>

    <div class="check-card full-width">
      <div class="card-header">
        <span class="card-icon"><i class="ph ph-path"></i></span>
        <span class="card-title">Delivery Path (Received Chain)</span>
        <span class="card-badge pass">${chain.length} hop${chain.length !== 1 ? 's' : ''}</span>
      </div>
      <div class="card-body">
        ${chain.length ? `<div class="hop-chain">${hops}</div>` : stateHtml('missing', 'No Received headers found')}
      </div>
    </div>`;
}

// ── UI helpers ─────────────────────────────────────────────────────────────

function showResultsSection() {
  const el = document.getElementById('results');
  el.style.display = 'block';
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function setAllLoading() {
  ['mx','spf','dmarc','dkim','bimi','blacklist','smtp'].forEach(t => setCardLoading(t));
  document.getElementById('scoreGrade').textContent = '—';
  document.getElementById('scoreNumber').textContent = '—/100';
  document.getElementById('scoreIssues').innerHTML = '';
}

function setCardLoading(type) {
  setBadge(type, 'loading', 'Checking…');
  setBody(type, '<div class="card-skeleton"></div>');
}

function setBadge(type, cls, text) {
  const el = document.getElementById(`badge-${type}`);
  if (el) { el.className = `card-badge ${cls}`; el.textContent = text; }
}

function setBody(type, html) {
  const el = document.getElementById(`body-${type}`);
  if (el) el.innerHTML = html;
}

function setProgress(pct) {
  const bar = document.getElementById('progressBar');
  const fill = document.getElementById('progressFill');
  bar.style.display = 'block';
  fill.style.width = pct + '%';
}

function hideProgress() {
  document.getElementById('progressBar').style.display = 'none';
}

function recordBlock(record) {
  if (!record) return '';
  return `<div class="record-block">
    <button class="copy-btn" onclick="copyText(this, ${JSON.stringify(record)})">Copy</button>${esc(record)}
  </div>`;
}

function tagPill(key, value, highlight = false) {
  return `<div class="tag-pill${highlight ? ' highlight' : ''}"><span>${esc(String(key))}:</span><strong>${esc(String(value))}</strong></div>`;
}

function findingsHtml(items) {
  if (!items?.length) return '';
  return `<div class="findings">${items.map(i => `
    <div class="finding ${i.severity || 'info'}">
      <i class="ph ${sevIcon(i.severity)}"></i>
      ${esc(i.text)}
    </div>`).join('')}</div>`;
}

function stateHtml(status, msg) {
  const cls = status === 'error' ? 'state-error' : 'state-missing';
  const icon = status === 'error' ? 'ph-x-circle' : 'ph-minus-circle';
  return `<div class="${cls}"><i class="ph ${icon}"></i><span>${esc(msg || status)}</span></div>`;
}

function sevIcon(sev) {
  const map = { pass: 'ph-check-circle', warn: 'ph-warning', fail: 'ph-x-circle', info: 'ph-info' };
  return map[sev] || 'ph-info';
}

function warnLevel(msg) {
  const m = msg.toLowerCase();
  if (m.includes('+all') || m.includes('too many') || m.includes('permerror')) return 'fail';
  return 'warn';
}

function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
}

function flashInput() {
  const el = document.getElementById('domainInput');
  el.style.borderColor = 'var(--fail)';
  el.focus();
  setTimeout(() => { el.style.borderColor = ''; }, 1500);
}

function showToast(msg, type = 'info') {
  let t = document.getElementById('__toast');
  if (!t) {
    t = document.createElement('div');
    t.id = '__toast';
    Object.assign(t.style, {
      position: 'fixed', bottom: '24px', right: '24px', zIndex: 9999,
      padding: '12px 20px', borderRadius: '8px', fontSize: '13px',
      fontWeight: '600', maxWidth: '320px', transition: 'opacity 0.3s',
      boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
    });
    document.body.appendChild(t);
  }
  const colors = { pass: '#22c55e', fail: '#ef4444', warn: '#f59e0b', info: '#6366f1' };
  t.style.background = colors[type] || colors.info;
  t.style.color = '#fff';
  t.style.opacity = '1';
  t.textContent = msg;
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.opacity = '0'; }, 3500);
}

// ── API ────────────────────────────────────────────────────────────────────

async function post(path, body) {
  const resp = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(text || `HTTP ${resp.status}`);
  }
  return resp.json();
}
