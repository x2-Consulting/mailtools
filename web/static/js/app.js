'use strict';

let lastDomain = '';
let lastResults = null;

// ── View switching ────────────────────────────────────────────────────────
function switchView(name) {
  document.querySelectorAll('.view').forEach(v => { v.style.display = 'none'; v.classList.remove('active'); });
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  const view = document.getElementById(`view-${name}`);
  if (view) { view.style.display = 'block'; view.classList.add('active'); }
  const btn = document.querySelector(`[data-view="${name}"]`);
  if (btn) btn.classList.add('active');
}

// ── Domain checker ────────────────────────────────────────────────────────
function getDomain() { return document.getElementById('domainInput').value.trim(); }
function getSelectors() {
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
    const data = await post('/check', { domain, dkim_selectors: getSelectors() });
    lastResults = data;
    setProgress(100);
    renderScore(data.score);
    renderMX(data.mx);
    renderSPF(data.spf);
    renderSPFChain(data.spf_chain);
    renderDMARC(data.dmarc);
    renderDKIM(data.dkim);
    renderBIMI(data.bimi);
    renderMTASTS(data.mta_sts, data.tls_rpt);
    renderDANE(data.dane);
    renderBlacklist(data.blacklist);
    renderIPRep(data.ip_reputation);
    renderWHOIS(data.whois);
    renderSMTP(data.smtp);
    renderRelay(data.open_relay, data.catch_all);
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
  setProgress(20);

  // Map type to card ID and render function
  const map = {
    'mx':            { card: 'mx',            fn: d => renderMX(d) },
    'spf':           { card: 'spf',           fn: d => renderSPF(d) },
    'spf-chain':     { card: 'spf_chain',     fn: d => renderSPFChain(d) },
    'dmarc':         { card: 'dmarc',         fn: d => renderDMARC(d) },
    'dkim':          { card: 'dkim',          fn: d => renderDKIM(d) },
    'bimi':          { card: 'bimi',          fn: d => renderBIMI(d) },
    'mta-sts':       { card: 'mta_sts',       fn: d => renderMTASTS(d.mta_sts, d.tls_rpt) },
    'dane':          { card: 'dane',          fn: d => renderDANE(d) },
    'blacklist':     { card: 'blacklist',     fn: d => renderBlacklist(d) },
    'smtp':          { card: 'smtp',          fn: d => renderSMTP(d) },
    'relay':         { card: 'relay',         fn: d => renderRelay(d, null) },
    'catchall':      { card: 'relay',         fn: d => renderRelay(null, d) },
    'whois':         { card: 'whois',         fn: d => renderWHOIS(d) },
    'ip-reputation': { card: 'ip_reputation', fn: d => renderIPRep(d) },
  };
  const entry = map[type];
  if (entry) setCardLoading(entry.card);

  try {
    const data = await post(`/check/${type}`, { domain, dkim_selectors: getSelectors() });
    setProgress(100);
    if (entry) entry.fn(data);
    setTimeout(() => hideProgress(), 500);
  } catch (e) {
    setProgress(0);
    showToast('Request failed: ' + e.message, 'fail');
  }
}

// ── Help panel ────────────────────────────────────────────────────────────
function toggleHelp(type) {
  const el = document.getElementById(`help-${type}`);
  if (!el) return;
  const open = el.style.display !== 'none';
  el.style.display = open ? 'none' : 'block';
  // Show generator if record is missing
  if (!open) {
    const genId = `gen-${type}`;
    const gen = document.getElementById(genId);
    if (gen) {
      const badge = document.getElementById(`badge-${type}`);
      const isMissing = badge && (badge.classList.contains('missing') || badge.textContent.toLowerCase().includes('missing'));
      gen.style.display = isMissing ? 'block' : 'block'; // always show generator when help is open
    }
  }
}

// ── Record generators ─────────────────────────────────────────────────────
function generateSPF() {
  const ip = document.getElementById('spf-ip').value.trim();
  const provider = document.getElementById('spf-provider').value;
  const policy = document.getElementById('spf-policy').value;

  let parts = ['v=spf1'];
  if (ip) parts.push(ip.includes('.') && !ip.includes(' ') ? (ip.match(/^[\d.]+/) ? `ip4:${ip}` : `a:${ip}`) : `a:${ip}`);
  if (provider) parts.push(provider);
  parts.push(policy);

  const record = parts.join(' ');
  showGenOutput('spf-output',
    [{ type: 'TXT', name: `${lastDomain || 'yourdomain.com'}`, value: record,
       where: 'Add as a TXT record at your domain root (@)' }]);
}

function generateDMARC() {
  const policy = document.getElementById('dmarc-policy').value;
  const rua    = document.getElementById('dmarc-rua').value.trim();
  const ruf    = document.getElementById('dmarc-ruf').value.trim();
  const pct    = document.getElementById('dmarc-pct').value;

  let parts = ['v=DMARC1', `p=${policy}`];
  if (rua) parts.push(`rua=mailto:${rua}`);
  if (ruf) parts.push(`ruf=mailto:${ruf}`);
  if (pct && pct !== '100') parts.push(`pct=${pct}`);
  parts.push('adkim=r', 'aspf=r');

  const record = parts.join('; ');
  showGenOutput('dmarc-output',
    [{ type: 'TXT', name: `_dmarc.${lastDomain || 'yourdomain.com'}`, value: record,
       where: 'Add as a TXT record at _dmarc.yourdomain.com' }]);
}

function generateBIMI() {
  const logo = document.getElementById('bimi-logo').value.trim();
  const vmc  = document.getElementById('bimi-vmc').value.trim();

  let parts = ['v=BIMI1'];
  parts.push(`l=${logo || ''}`);
  if (vmc) parts.push(`a=${vmc}`);

  const record = parts.join('; ');
  showGenOutput('bimi-output',
    [{ type: 'TXT', name: `default._bimi.${lastDomain || 'yourdomain.com'}`, value: record,
       where: 'Add as a TXT record at default._bimi.yourdomain.com' }]);
}

function generateMTASTS() {
  const id     = document.getElementById('mta-id').value.trim() || Date.now().toString();
  const email  = document.getElementById('tls-rpt-email').value.trim();
  const domain = lastDomain || 'yourdomain.com';

  showGenOutput('mta-sts-output', [
    {
      type: 'TXT — MTA-STS DNS record',
      name: `_mta-sts.${domain}`,
      value: `v=STSv1; id=${id}`,
      where: 'Add as TXT at _mta-sts.yourdomain.com'
    },
    {
      type: 'TXT — TLS-RPT',
      name: `_smtp._tls.${domain}`,
      value: `v=TLSRPTv1; rua=mailto:${email || 'tls-reports@' + domain}`,
      where: 'Add as TXT at _smtp._tls.yourdomain.com'
    },
    {
      type: 'Policy file (HTTPS)',
      name: `https://mta-sts.${domain}/.well-known/mta-sts.txt`,
      value: `version: STSv1\nmode: enforce\nmx: mail.${domain}\nmax_age: 86400`,
      where: `Host this file at https://mta-sts.${domain}/.well-known/mta-sts.txt (requires valid TLS cert)`
    }
  ]);
}

function showGenOutput(elId, records) {
  const el = document.getElementById(elId);
  if (!el) return;
  el.style.display = 'block';
  el.innerHTML = records.map(r => `
    <div style="margin-bottom:${records.length > 1 ? '12px' : '0'}">
      <div class="dns-type">${esc(r.type)}</div>
      <div class="dns-where">Hostname: <strong>${esc(r.name)}</strong></div>
      <div class="dns-where">${esc(r.where)}</div>
      <div class="dns-record">${esc(r.value)}</div>
      <button class="copy-btn" style="position:static;margin-top:4px" onclick="copyText(this, ${JSON.stringify(r.value)})">Copy</button>
    </div>`).join('');
}

// ── PDF export ────────────────────────────────────────────────────────────
async function exportPDF() {
  const domain = lastDomain || getDomain();
  if (!domain) { flashInput(); return; }
  showToast('Generating PDF report…', 'info');
  try {
    const resp = await fetch('/report/pdf', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain, dkim_selectors: getSelectors() }),
    });
    if (!resp.ok) throw new Error(await resp.text());
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `mailcheck-${domain}.pdf`; a.click();
    URL.revokeObjectURL(url);
    showToast('PDF downloaded', 'pass');
  } catch (e) { showToast('PDF failed: ' + e.message, 'fail'); }
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
  } catch (e) { setProgress(0); showToast('Analysis failed: ' + e.message, 'fail'); }
}

// ── Renderers ─────────────────────────────────────────────────────────────

function renderScore(score) {
  if (!score) return;
  const grade = score.grade || '—';
  const el = document.getElementById('scoreGrade');
  el.textContent = grade;
  el.className = `score-grade grade-${grade}`;
  document.getElementById('scoreNumber').textContent = `${score.score}/100`;
  const issuesEl = document.getElementById('scoreIssues');
  issuesEl.innerHTML = (score.issues || []).map(i =>
    `<li class="score-issue"><span class="issue-dot ${i.severity}"></span><span>${esc(i.text)}</span></li>`
  ).join('');
}

function renderMX(data) {
  const sev = data.status === 'ok' ? 'pass' : 'fail';
  setBadge('mx', sev, data.status === 'ok' ? 'Pass' : data.status);
  if (!data.records?.length) { setBody('mx', stateHtml(data.status, data.error || 'No MX records found')); return; }
  setBody('mx', `
    <table class="mx-table">
      <thead><tr><th>Priority</th><th>Host</th><th>IP</th><th>PTR (rDNS)</th></tr></thead>
      <tbody>${data.records.map(r => `
        <tr>
          <td><span class="priority-badge">${r.priority}</span></td>
          <td><span class="host-name">${esc(r.host)}</span></td>
          <td><span class="ip-text">${esc(r.ip || '—')}</span></td>
          <td><span class="ptr-text">${esc(r.ptr || '—')}</span></td>
        </tr>`).join('')}
      </tbody>
    </table>`);
}

function renderSPF(data) {
  if (data.status === 'missing' || data.status === 'error') {
    setBadge('spf', data.status, data.status);
    setBody('spf', stateHtml(data.status, data.error || 'No SPF record found'));
    _showGenerator('spf');
    return;
  }
  const parsed = data.parsed || {};
  const warnings = parsed.warnings || [];
  const hasFail = warnings.some(w => w.includes('+all') || w.includes('Too many'));
  setBadge('spf', hasFail ? 'fail' : warnings.length ? 'warn' : 'pass',
           hasFail ? 'Fail' : warnings.length ? 'Warning' : 'Pass');
  setBody('spf', `
    ${recordBlock(data.record)}
    <div class="tag-grid">
      ${tagPill('Version', parsed.version || 'spf1')}
      ${tagPill('All', parsed.all_mechanism || 'none', true)}
      ${tagPill('Lookups', `${parsed.lookup_count || 0}/10`, (parsed.lookup_count || 0) > 10)}
      ${tagPill('Includes', parsed.includes?.length || 0)}
      ${tagPill('IP4 ranges', parsed.ip4?.length || 0)}
      ${tagPill('IP6 ranges', parsed.ip6?.length || 0)}
    </div>
    ${findingsHtml(warnings.map(w => ({ severity: warnLevel(w), text: w })))}`);
}

function renderSPFChain(data) {
  if (!data || data.status === 'missing') {
    setBadge('spf_chain', 'missing', 'No SPF');
    setBody('spf_chain', stateHtml('missing', 'No SPF record to expand'));
    return;
  }
  const over = data.total_lookups > 10;
  setBadge('spf_chain', over ? 'fail' : 'pass',
           `${data.total_lookups}/10 lookups · ${data.total_ip4 + data.total_ip6} IPs`);

  const header = `
    <div class="tag-grid" style="margin-bottom:12px">
      ${tagPill('Total Lookups', `${data.total_lookups}/10`, over)}
      ${tagPill('IPv4 ranges', data.total_ip4)}
      ${tagPill('IPv6 ranges', data.total_ip6)}
    </div>
    ${over ? findingsHtml([{severity:'fail', text:'SPF lookup count exceeds 10 — receiving servers will return a permerror and reject email'}]) : ''}`;

  setBody('spf_chain', header + '<div class="spf-tree">' + renderSPFNode(data.tree, true) + '</div>');
}

function renderSPFNode(node, isRoot) {
  if (!node) return '';
  const cls = isRoot ? 'spf-node-root' : '';
  const redirect = node._is_redirect ? '<span class="spf-redirect-badge">redirect</span>' : '';
  const ips = [...(node.direct_ip4 || []), ...(node.direct_ip6 || [])];
  const ipStr = ips.length ? `<div class="spf-node-ips">${ips.slice(0,6).map(esc).join(', ')}${ips.length > 6 ? ` +${ips.length-6} more` : ''}</div>` : '';
  const error = node.error ? `<div class="spf-node-error">${esc(node.error)}</div>` : '';
  const children = (node.includes || []).map(c => renderSPFNode(c, false)).join('');
  return `<div class="spf-node ${cls}">
    <div class="spf-node-domain">${esc(node.domain)}${redirect}</div>
    ${node.all_mechanism ? `<div class="spf-node-ips">all: <code>${esc(node.all_mechanism)}</code></div>` : ''}
    ${ipStr}${error}
    ${children}
  </div>`;
}

function renderDMARC(data) {
  if (data.status === 'missing' || data.status === 'error') {
    setBadge('dmarc', data.status, data.status);
    setBody('dmarc', stateHtml(data.status, data.error || 'No DMARC record found'));
    _showGenerator('dmarc');
    return;
  }
  const parsed = data.parsed || {};
  const warnings = parsed.warnings || [];
  const policy = data.policy || parsed.p || 'none';
  const badgeSev = policy === 'reject' ? 'pass' : policy === 'quarantine' ? 'warn' : 'warn';
  setBadge('dmarc', badgeSev, `Policy: ${policy}`);
  const findings = warnings.map(w => ({ severity: 'warn', text: w }));
  if (parsed.rua) findings.unshift({ severity: 'pass', text: `Aggregate reports → ${parsed.rua}` });
  if (parsed.ruf) findings.unshift({ severity: 'pass', text: `Forensic reports → ${parsed.ruf}` });
  setBody('dmarc', `
    ${recordBlock(data.record)}
    <div class="tag-grid">
      ${tagPill('Policy', parsed.p || 'none', true)}
      ${tagPill('Sub Policy', parsed.sp || 'inherit')}
      ${tagPill('DKIM Align', parsed.adkim === 's' ? 'strict' : 'relaxed')}
      ${tagPill('SPF Align', parsed.aspf === 's' ? 'strict' : 'relaxed')}
      ${tagPill('Pct', `${parsed.pct || 100}%`)}
    </div>
    ${findingsHtml(findings)}`);
}

function renderDKIM(data) {
  const found = data.found_selectors || [];
  if (!found.length) {
    setBadge('dkim', 'missing', 'Not Found');
    setBody('dkim', stateHtml('missing', `No DKIM records found — checked ${data.selectors_checked || 0} selectors automatically`));
    return;
  }
  setBadge('dkim', 'pass', `${found.length} selector${found.length > 1 ? 's' : ''}`);
  setBody('dkim', `
    <div class="finding info"><i class="ph ph-info"></i>Auto-detected: checked ${data.selectors_checked} selectors</div>
    <div style="margin-top:10px" class="selector-list">${found.map(sel => {
      const p = sel.parsed || {};
      return `<div class="selector-item">
        <div class="selector-name">${esc(sel.selector)}</div>
        <div class="selector-fqdn">${esc(sel.fqdn)}</div>
        <div class="tag-grid">
          ${tagPill('Type', p.key_type || 'rsa')}
          ${tagPill('Status', p.key_revoked ? 'REVOKED' : 'Active', p.key_revoked)}
        </div>
        ${recordBlock(sel.record)}
        ${findingsHtml((p.warnings||[]).map(w=>({severity:'warn',text:w})))}
      </div>`;
    }).join('')}</div>`);
}

function renderBIMI(data) {
  if (data.status === 'missing') {
    setBadge('bimi', 'missing', 'Not Configured');
    setBody('bimi', stateHtml('missing', 'No BIMI record — requires DMARC p=quarantine or p=reject'));
    _showGenerator('bimi');
    return;
  }
  if (data.status === 'error') { setBadge('bimi','fail','Error'); setBody('bimi', stateHtml('error', data.error)); return; }
  const parsed = data.parsed || {};
  const warnings = parsed.warnings || [];
  setBadge('bimi', warnings.length ? 'warn' : 'pass', warnings.length ? 'Partial' : 'Pass');
  const logoUrl = data.logo_url;
  setBody('bimi', `
    ${logoUrl ? `<div class="bimi-wrap">
      <img class="bimi-logo" src="${esc(logoUrl)}" alt="BIMI logo" onerror="this.style.display='none'"/>
      <div style="flex:1">${recordBlock(data.record)}</div>
    </div>` : recordBlock(data.record)}
    <div class="tag-grid">
      ${tagPill('Selector', data.selector || 'default')}
      ${tagPill('Logo', logoUrl ? 'Present' : 'Missing', !logoUrl)}
      ${tagPill('VMC', data.vmc_url ? 'Present' : 'Missing', !data.vmc_url)}
    </div>
    ${findingsHtml(warnings.map(w=>({severity:'warn',text:w})))}`);
}

function renderMTASTS(mta, tls) {
  const mtaOk = mta?.status === 'ok';
  const tlsOk = tls?.status === 'ok';
  setBadge('mta_sts', mtaOk ? 'pass' : mta?.status === 'missing' ? 'missing' : 'warn',
           mtaOk ? (mta.policy?.mode || 'ok') : 'Not Configured');

  if (!mta && !tls) { setBody('mta_sts', stateHtml('missing', 'No data')); return; }

  const mtaWarnings = (mta?.warnings || []).map(w => ({severity:'warn', text:w}));
  const tlsWarnings = ((tls?.parsed?.warnings) || []).map(w => ({severity:'warn', text:w}));
  const policy = mta?.policy;

  setBody('mta_sts', `
    <div class="mta-sts-grid">
      <div class="mta-block">
        <div class="mta-block-title"><i class="ph ph-lock-simple"></i> MTA-STS</div>
        ${mta?.dns_record ? recordBlock(mta.dns_record) : `<div class="finding fail"><i class="ph ph-x-circle"></i>No DNS record</div>`}
        ${policy ? `<div class="tag-grid">
          ${tagPill('Mode', policy.mode || '?', policy.mode !== 'enforce')}
          ${tagPill('Max Age', policy.max_age ? `${policy.max_age}s` : '?')}
          ${tagPill('Cert', mta.cert_valid === true ? 'Valid' : mta.cert_valid === false ? 'INVALID' : '?', mta.cert_valid === false)}
          ${tagPill('MX entries', policy.mx?.length || 0)}
        </div>` : ''}
        ${findingsHtml(mtaWarnings)}
        ${!mta?.dns_record ? `<div style="margin-top:8px"><button class="btn-generate" onclick="toggleHelp('mta_sts')"><i class="ph ph-magic-wand"></i> Generate Records</button></div>` : ''}
      </div>
      <div class="mta-block">
        <div class="mta-block-title"><i class="ph ph-file-text"></i> TLS-RPT</div>
        ${tls?.record ? recordBlock(tls.record) : `<div class="finding ${tls?.status === 'missing' ? 'fail' : 'info'}"><i class="ph ph-${tls?.status === 'missing' ? 'x-circle' : 'info'}"></i>${tls?.error || 'No TLS-RPT record'}</div>`}
        ${tls?.parsed?.rua ? `<div class="finding pass"><i class="ph ph-check-circle"></i>Reports → ${esc(tls.parsed.rua)}</div>` : ''}
        ${findingsHtml(tlsWarnings)}
      </div>
    </div>`);
}

function renderDANE(data) {
  if (data.status === 'missing') {
    setBadge('dane', 'missing', 'Not Configured');
    setBody('dane', stateHtml('missing', 'No DANE/TLSA records found — requires DNSSEC on your domain'));
    return;
  }
  setBadge('dane', 'pass', 'Configured');
  setBody('dane', (data.results || []).map(r => {
    if (r.status !== 'ok') return `<div class="dane-host">${esc(r.host)}</div><div class="finding ${r.status === 'missing' ? 'info' : 'fail'}"><i class="ph ph-info"></i>${esc(r.error || 'Not found')}</div>`;
    return `<div class="dane-host">${esc(r.host)}</div>
      <div class="dane-fqdn">${esc(r.fqdn)}</div>
      ${r.records.map(rec => `<div class="tlsa-record">
        <div class="tlsa-tags">
          ${tagPill('Usage', `${rec.usage} (${rec.usage_name})`)}
          ${tagPill('Selector', `${rec.selector} (${rec.selector_name})`)}
          ${tagPill('Match', `${rec.mtype} (${rec.mtype_name})`)}
        </div>
        <div class="tlsa-cert">${esc(rec.cert_hex)}</div>
      </div>`).join('')}`;
  }).join('<hr style="border:none;border-top:1px solid var(--border);margin:12px 0">'));
}

function renderBlacklist(data) {
  if (data.status === 'error') { setBadge('blacklist','fail','Error'); setBody('blacklist', stateHtml('error', data.error)); return; }
  const listed = data.listed || [];
  setBadge('blacklist', listed.length ? 'fail' : 'pass', listed.length ? `${listed.length} Listed` : 'Clean');
  const ips = (data.ips_checked || []).map(ip => `<span class="ip-text" style="margin-right:6px">${esc(ip)}</span>`).join('');
  const summary = `<div class="bl-summary">Checked <strong>${data.lists_checked||0}</strong> RBLs for ${ips}
    ${listed.length === 0
      ? `<div class="finding pass" style="margin-top:8px"><i class="ph ph-check-circle"></i>All clean</div>`
      : `<span style="color:var(--fail)"><strong>${listed.length}</strong> listing(s)</span>`}
  </div>`;
  const listedHtml = listed.length
    ? `<div class="bl-listed">${listed.map(e => `<div class="bl-item">
        <div class="bl-name">${esc(e.name)}</div>
        <div class="bl-reason">${esc(e.reason || 'No reason provided')}</div>
        <div class="bl-code">Return: ${esc((e.return_codes||[]).join(', '))}</div>
      </div>`).join('')}</div>` : '';
  setBody('blacklist', summary + listedHtml);
}

function renderIPRep(data) {
  if (!data || data.status === 'error') { setBadge('ip_reputation','fail','Error'); setBody('ip_reputation', stateHtml('error', data?.error || 'Lookup failed')); return; }
  setBadge('ip_reputation', 'pass', `${(data.results||[]).length} IP(s)`);
  setBody('ip_reputation', (data.results || []).map(r => {
    if (r.status === 'error') return `<div class="ip-rep-item"><div class="ip-rep-ip">${esc(r.ip)}</div><div class="finding fail"><i class="ph ph-x-circle"></i>${esc(r.error)}</div></div>`;
    return `<div class="ip-rep-item">
      <div class="ip-rep-ip">${esc(r.ip)}</div>
      <div class="ip-rep-grid">
        <span>Organisation</span><span>${esc(r.org_name || '—')}</span>
        <span>Country</span><span>${esc(r.country || '—')}</span>
        <span>Network</span><span>${esc(r.cidr || '—')}</span>
        <span>Abuse Email</span><span>${r.abuse_email ? `<a href="mailto:${esc(r.abuse_email)}" style="color:var(--accent)">${esc(r.abuse_email)}</a>` : '—'}</span>
      </div>
    </div>`;
  }).join('') || stateHtml('missing', 'No IP data'));
}

function renderWHOIS(data) {
  if (data.status === 'error') { setBadge('whois','fail','Error'); setBody('whois', stateHtml('error', data.error)); return; }
  const age = data.domain_age_days;
  const ageCls = age !== null ? (age < 30 ? 'age-young' : age < 365 ? 'age-new' : 'age-ok') : '';
  const ageStr = age !== null ? `${age} days` : '—';
  setBadge('whois', data.warnings?.length ? (age !== null && age < 30 ? 'fail' : 'warn') : 'pass',
           ageStr !== '—' ? `${ageStr} old` : 'ok');
  setBody('whois', `
    <div class="whois-grid">
      <div class="whois-item"><div class="whois-label">Registrar</div><div class="whois-value">${esc(data.registrar || '—')}</div></div>
      <div class="whois-item"><div class="whois-label">Domain Age</div><div class="whois-value ${ageCls}">${esc(ageStr)}</div></div>
      <div class="whois-item"><div class="whois-label">Created</div><div class="whois-value">${esc(data.created ? data.created.split('T')[0] : '—')}</div></div>
      <div class="whois-item"><div class="whois-label">Expires</div><div class="whois-value ${data.days_to_expiry !== null && data.days_to_expiry < 30 ? 'age-young' : ''}">${esc(data.expires ? data.expires.split('T')[0] : '—')}</div></div>
      <div class="whois-item"><div class="whois-label">Last Updated</div><div class="whois-value">${esc(data.updated ? data.updated.split('T')[0] : '—')}</div></div>
      <div class="whois-item"><div class="whois-label">Nameservers</div><div class="whois-value" style="font-size:11px">${esc((data.nameservers||[]).slice(0,3).join(', ') || '—')}</div></div>
    </div>
    ${data.status_flags?.length ? `<div class="tag-grid" style="margin-top:10px">${data.status_flags.map(f=>tagPill('Status', f)).join('')}</div>` : ''}
    ${findingsHtml((data.warnings||[]).map(w=>({severity:'warn',text:w})))}`);
}

function renderSMTP(data) {
  if (data.status === 'error' && !data.results?.length) { setBadge('smtp','fail','Error'); setBody('smtp', stateHtml('error', data.error || 'No SMTP results')); return; }
  const results = data.results || [];
  const anyConn = results.some(r => r.connected);
  const anyTLS  = results.some(r => r.tls_established);
  setBadge('smtp', !anyConn ? 'fail' : !anyTLS ? 'warn' : 'pass',
           !anyConn ? 'Unreachable' : !anyTLS ? 'No TLS' : 'Pass');
  setBody('smtp', `<div class="smtp-grid">${results.map(r => {
    if (!r.connected) return `<div class="smtp-row"><div class="smtp-host">${esc(r.host)}</div>
      <div class="smtp-meta"><span class="smtp-port">${r.port}</span><span style="color:var(--fail)">${esc(r.error||'Failed')}</span></div></div>`;
    const tls = r.tls_established
      ? `<span class="tls-pill ok"><i class="ph ph-lock-simple"></i>${esc(r.tls_version||'TLS')} · ${esc(r.cipher||'')}</span>`
      : `<span class="tls-pill none"><i class="ph ph-lock-simple-open"></i>${r.starttls_available === false ? 'No STARTTLS' : 'Unencrypted'}</span>`;
    const feats = (r.ehlo_features||[]).slice(0,8).join(', ');
    return `<div class="smtp-row">
      <div class="smtp-host">${esc(r.host)}</div>
      <div class="smtp-meta"><span class="smtp-port">${r.port}</span><b>${r.latency_ms}ms</b>
        ${r.cert_cn ? ` · Cert: ${esc(r.cert_cn)}` : ''}
        ${r.cert_expiry ? ` · Exp: ${esc(r.cert_expiry)}` : ''}
      </div>
      ${tls}
      ${feats ? `<div class="smtp-meta" style="margin-top:5px">EHLO: ${esc(feats)}</div>` : ''}
      ${r.banner ? `<div class="smtp-banner">${esc(r.banner)}</div>` : ''}
    </div>`;
  }).join('')}</div>`);
}

function renderRelay(relay, catchAll) {
  const relayOpen = relay?.open_relay_count > 0;
  const isCatchAll = catchAll?.is_catch_all;
  const sev = relayOpen ? 'fail' : isCatchAll ? 'warn' : 'pass';
  const label = relayOpen ? 'Open Relay!' : isCatchAll ? 'Catch-All' : 'Pass';
  setBadge('relay', sev, label);

  const relayHtml = relay
    ? `<div class="relay-block">
        <div class="relay-title" style="color:${relayOpen ? 'var(--fail)' : 'var(--pass)'}">
          <i class="ph ph-${relayOpen ? 'warning' : 'check-circle'}"></i> Open Relay
        </div>
        ${relay.results?.map(r => `<div class="relay-result">
          <b>${esc(r.host)}</b> — ${r.is_open_relay
            ? '<span style="color:var(--fail)">OPEN RELAY DETECTED</span>'
            : r.error ? `<span style="color:var(--text-dim)">${esc(r.error)}</span>`
            : '<span style="color:var(--pass)">Properly protected</span>'}
          ${r.response ? `<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);margin-top:2px">${esc(r.response)}</div>` : ''}
        </div>`).join('') || ''}
      </div>`
    : `<div class="relay-block"><div class="mta-block-title">Open Relay</div><div class="finding info"><i class="ph ph-info"></i>Run full check for relay test</div></div>`;

  const catchHtml = catchAll
    ? `<div class="relay-block">
        <div class="relay-title" style="color:${isCatchAll ? 'var(--warn)' : 'var(--pass)'}">
          <i class="ph ph-${isCatchAll ? 'warning' : 'check-circle'}"></i> Catch-All
        </div>
        ${catchAll.results?.map(r => `<div class="relay-result">
          <b>${esc(r.host)}</b> — ${r.is_catch_all
            ? '<span style="color:var(--warn)">Catch-all enabled</span>'
            : r.error ? `<span style="color:var(--text-dim)">${esc(r.error)}</span>`
            : '<span style="color:var(--pass)">Rejects unknown recipients</span>'}
          ${r.test_address ? `<div style="font-size:10px;color:var(--text-dim);font-family:var(--mono);margin-top:2px">Tested: ${esc(r.test_address)}</div>` : ''}
        </div>`).join('') || ''}
      </div>`
    : `<div class="relay-block"><div class="mta-block-title">Catch-All</div><div class="finding info"><i class="ph ph-info"></i>Run full check for catch-all test</div></div>`;

  setBody('relay', `<div class="relay-grid">${relayHtml}${catchHtml}</div>`);
}

// ── Header analysis renderer ───────────────────────────────────────────────
function renderHeaderResults(data) {
  const cardsEl = document.getElementById('header-cards');
  if (data.status === 'error') { cardsEl.innerHTML = `<div class="check-card full-width"><div class="card-body">${stateHtml('error', data.error)}</div></div>`; return; }

  const s = data.summary || {};
  const auth = data.authentication || {};
  const anomalies = data.anomalies || [];
  const chain = data.received_chain || [];
  const alignment = data.alignment || {};
  const urls = data.urls || {};

  const authPills = ['spf','dkim','dmarc'].flatMap(proto =>
    (auth[proto]||[]).map(e => {
      const cls = e.result === 'pass' ? 'pass' : ['fail','hardfail','permerror'].includes(e.result) ? 'fail' : 'neutral';
      return `<span class="auth-pill ${cls}">${proto.toUpperCase()}: ${esc(e.result)}</span>`;
    })
  ).join('') || '<span class="auth-pill neutral">No auth results</span>';

  const summaryRows = [
    ['From', s.from], ['To', s.to], ['Subject', s.subject],
    ['Date', s.date], ['Message-ID', s.message_id],
    ['Return-Path', s.return_path], ['Reply-To', s.reply_to || '—'],
    ['Delivery Time', s.delivery_time_seconds != null ? `${Math.round(s.delivery_time_seconds)}s` : '—'],
  ].filter(([,v]) => v).map(([k,v]) =>
    `<tr><td style="color:var(--text-dim);padding:5px 8px;white-space:nowrap;font-size:12px">${k}</td>
         <td style="padding:5px 8px;font-family:var(--mono);font-size:12px;word-break:break-all">${esc(v)}</td></tr>`
  ).join('');

  const alignItems = [
    { label: 'From / Return-Path', val: alignment.from_return_path_match },
    { label: 'From / Reply-To',    val: alignment.from_reply_to_match },
  ].filter(a => a.val !== null && a.val !== undefined).map(a =>
    `<div class="finding ${a.val ? 'pass' : 'warn'}"><i class="ph ph-${a.val ? 'check-circle' : 'warning'}"></i>${a.label}: ${a.val ? 'Aligned' : 'Mismatch'}</div>`
  ).join('');

  const hops = chain.map((h, i) => `
    <div class="hop" data-n="${i+1}">
      <div class="hop-from">${esc(h.from || '?')} ${h.ip ? `[${esc(h.ip)}]` : ''}</div>
      ${h.by ? `<div class="hop-by">→ ${esc(h.by)} via ${esc(h.with || '?')}</div>` : ''}
      ${h.timestamp ? `<div class="hop-ts">${esc(h.timestamp)}</div>` : ''}
      ${h.tls ? '<span class="hop-tls"><i class="ph ph-lock-simple"></i>TLS</span>'
               : (h.from ? '<span class="hop-notls"><i class="ph ph-lock-simple-open"></i>No TLS</span>' : '')}
    </div>`).join('');

  const anomalyHtml = anomalies.length
    ? findingsHtml(anomalies.map(a => ({ severity: a.severity === 'fail' ? 'fail' : 'warn', text: a.message })))
    : `<div class="finding pass"><i class="ph ph-check-circle"></i>No anomalies detected</div>`;

  const urlHtml = urls.flagged_count > 0
    ? `<div class="finding warn" style="margin-bottom:8px"><i class="ph ph-warning"></i>${urls.flagged_count} URL(s) flagged</div>
       ${urls.flagged.map(u => `<div class="url-item">
         <div class="url-text">${esc(u.url)}</div>
         ${findingsHtml(u.flags)}
       </div>`).join('')}`
    : `<div class="finding pass"><i class="ph ph-check-circle"></i>${urls.total} URL(s) found, none flagged</div>`;

  cardsEl.innerHTML = `
    <div class="check-card">
      <div class="card-header"><span class="card-icon"><i class="ph ph-envelope-open"></i></span><span class="card-title">Message Summary</span></div>
      <div class="card-body"><table style="width:100%;border-collapse:collapse">${summaryRows}</table></div>
    </div>
    <div class="check-card">
      <div class="card-header"><span class="card-icon"><i class="ph ph-shield-check"></i></span><span class="card-title">Authentication</span></div>
      <div class="card-body">
        <div class="auth-results">${authPills}</div>
        <div class="section-label">Domain Alignment</div>
        <div class="findings">${alignItems || '<div class="finding info"><i class="ph ph-info"></i>No alignment data</div>'}</div>
      </div>
    </div>
    <div class="check-card">
      <div class="card-header"><span class="card-icon"><i class="ph ph-warning"></i></span><span class="card-title">Anomalies</span></div>
      <div class="card-body">${anomalyHtml}</div>
    </div>
    <div class="check-card">
      <div class="card-header"><span class="card-icon"><i class="ph ph-link"></i></span><span class="card-title">URL Analysis</span><span class="card-badge ${urls.flagged_count > 0 ? 'fail' : 'pass'}">${urls.total || 0} URLs</span></div>
      <div class="card-body">${urlHtml}</div>
    </div>
    <div class="check-card full-width">
      <div class="card-header"><span class="card-icon"><i class="ph ph-path"></i></span><span class="card-title">Delivery Path</span><span class="card-badge pass">${chain.length} hop${chain.length !== 1 ? 's' : ''}</span></div>
      <div class="card-body">${chain.length ? `<div class="hop-chain">${hops}</div>` : stateHtml('missing', 'No Received headers found')}</div>
    </div>`;
}

// ── UI helpers ─────────────────────────────────────────────────────────────
function showResultsSection() {
  const el = document.getElementById('results');
  el.style.display = 'block';
  el.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

const ALL_CARDS = ['mx','spf','spf_chain','dmarc','dkim','bimi','mta_sts','dane','blacklist','ip_reputation','whois','smtp','relay'];
function setAllLoading() {
  ALL_CARDS.forEach(t => setCardLoading(t));
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
  document.getElementById('progressBar').style.display = 'block';
  document.getElementById('progressFill').style.width = pct + '%';
}
function hideProgress() { document.getElementById('progressBar').style.display = 'none'; }

function _showGenerator(type) {
  const genEl = document.getElementById(`gen-${type}`);
  if (genEl) genEl.style.display = 'block';
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
  return `<div class="findings">${items.map(i =>
    `<div class="finding ${i.severity||'info'}"><i class="ph ${sevIcon(i.severity)}"></i>${esc(i.text)}</div>`
  ).join('')}</div>`;
}
function stateHtml(status, msg) {
  const cls = status === 'error' || status === 'fail' ? 'state-error' : 'state-missing';
  const icon = status === 'error' || status === 'fail' ? 'ph-x-circle' : 'ph-minus-circle';
  return `<div class="${cls}"><i class="ph ${icon}"></i><span>${esc(msg||status)}</span></div>`;
}
function sevIcon(sev) { return {pass:'ph-check-circle',warn:'ph-warning',fail:'ph-x-circle',info:'ph-info'}[sev]||'ph-info'; }
function warnLevel(msg) { return (msg.includes('+all')||msg.includes('Too many')) ? 'fail' : 'warn'; }
function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function copyText(btn, text) {
  navigator.clipboard.writeText(text).then(() => { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy'; }, 2000); });
}
function flashInput() { const el = document.getElementById('domainInput'); el.style.borderColor='var(--fail)'; el.focus(); setTimeout(()=>{el.style.borderColor='';},1500); }
function showToast(msg, type='info') {
  let t = document.getElementById('__toast');
  if (!t) { t=document.createElement('div'); t.id='__toast';
    Object.assign(t.style,{position:'fixed',bottom:'24px',right:'24px',zIndex:'9999',padding:'12px 20px',borderRadius:'8px',fontSize:'13px',fontWeight:'600',maxWidth:'320px',transition:'opacity 0.3s',boxShadow:'0 4px 20px rgba(0,0,0,0.4)'});
    document.body.appendChild(t); }
  const colors={pass:'#22c55e',fail:'#ef4444',warn:'#f59e0b',info:'#6366f1'};
  t.style.background=colors[type]||colors.info; t.style.color='#fff'; t.style.opacity='1'; t.textContent=msg;
  clearTimeout(t._timer); t._timer=setTimeout(()=>{t.style.opacity='0';},3500);
}
async function post(path, body) {
  const resp = await fetch(path, { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(body) });
  if (!resp.ok) { const text=await resp.text(); throw new Error(text||`HTTP ${resp.status}`); }
  return resp.json();
}
