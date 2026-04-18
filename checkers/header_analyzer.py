import re
import socket
from datetime import datetime, timezone
from email import message_from_string
from email.utils import parsedate_to_datetime
from typing import Optional


# ─── Public entry point ──────────────────────────────────────────────────────

def analyze_headers(raw: str) -> dict:
    # Normalize line endings and ensure double-CRLF if only headers provided
    raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    if '\n\n' not in raw:
        raw += '\n\n'

    try:
        msg = message_from_string(raw)
    except Exception as e:
        return {'status': 'error', 'error': f'Failed to parse headers: {e}'}

    received_chain = _parse_received(msg.get_all('Received') or [])
    auth_results = _parse_auth_results(msg.get_all('Authentication-Results') or [])
    arc_chain = _parse_arc(msg)
    dkim_sigs = _parse_dkim_sigs(msg.get_all('DKIM-Signature') or [])

    from_addr = msg.get('From', '')
    reply_to = msg.get('Reply-To', '')
    return_path = msg.get('Return-Path', '')
    from_domain = _extract_domain(from_addr)
    return_domain = _extract_domain(return_path)
    reply_domain = _extract_domain(reply_to)

    date_header = msg.get('Date', '')
    delivery_time = _calc_delivery(received_chain)

    spam_scores = _parse_spam_scores(msg)
    urls = _extract_urls(msg)
    url_findings = _analyse_urls(urls)
    timezone_anomalies = _check_timezone(date_header, received_chain)

    anomalies = _detect_anomalies(
        from_domain, return_domain, reply_domain, received_chain, auth_results, spam_scores
    ) + timezone_anomalies

    return {
        'status': 'ok',
        'summary': {
            'message_id': msg.get('Message-ID', ''),
            'subject': msg.get('Subject', ''),
            'from': from_addr,
            'to': msg.get('To', ''),
            'date': date_header,
            'reply_to': reply_to,
            'return_path': return_path,
            'delivery_time_seconds': delivery_time,
        },
        'authentication': auth_results,
        'dkim_signatures': dkim_sigs,
        'arc_chain': arc_chain,
        'received_chain': received_chain,
        'spam_scores': spam_scores,
        'urls': url_findings,
        'alignment': {
            'from_domain': from_domain,
            'return_path_domain': return_domain,
            'reply_to_domain': reply_domain,
            'from_return_path_match': _domains_align(from_domain, return_domain),
            'from_reply_to_match': _domains_align(from_domain, reply_domain) if reply_domain else None,
        },
        'anomalies': anomalies,
    }


# ─── Received chain ──────────────────────────────────────────────────────────

def _parse_received(headers: list) -> list:
    chain = []
    # Headers are in reverse-chronological order (latest first), reverse for display
    for h in reversed(headers):
        hop = {'raw': h, 'from': None, 'by': None, 'with': None, 'for': None,
               'timestamp': None, 'ip': None, 'rdns': None, 'tls': False}

        m = re.search(r'from\s+(\S+)\s*(?:\(([^)]+)\))?', h, re.IGNORECASE)
        if m:
            hop['from'] = m.group(1)
            inner = m.group(2) or ''
            ip_m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', inner)
            if ip_m:
                hop['ip'] = ip_m.group(1)
            rdns_m = re.search(r'([a-zA-Z0-9][\w.-]+)\s+\[', inner)
            if rdns_m:
                hop['rdns'] = rdns_m.group(1)

        by_m = re.search(r'by\s+(\S+)', h, re.IGNORECASE)
        if by_m:
            hop['by'] = by_m.group(1).rstrip(';')

        with_m = re.search(r'with\s+(\S+)', h, re.IGNORECASE)
        if with_m:
            hop['with'] = with_m.group(1)

        for_m = re.search(r'for\s+<([^>]+)>', h, re.IGNORECASE)
        if for_m:
            hop['for'] = for_m.group(1)

        # Extract timestamp (last semicolon-delimited part)
        ts_m = re.search(r';\s*(.+)$', h.strip())
        if ts_m:
            ts_raw = ts_m.group(1).strip()
            hop['timestamp'] = ts_raw
            try:
                hop['timestamp_parsed'] = parsedate_to_datetime(ts_raw).isoformat()
            except Exception:
                hop['timestamp_parsed'] = None

        if re.search(r'TLS|SMTPS|ESMTPS|STARTTLS', hop.get('with', '') or '', re.IGNORECASE):
            hop['tls'] = True

        chain.append(hop)

    return chain


def _calc_delivery(chain: list) -> Optional[float]:
    parsed = [h.get('timestamp_parsed') for h in chain if h.get('timestamp_parsed')]
    if len(parsed) < 2:
        return None
    try:
        t0 = datetime.fromisoformat(parsed[0])
        t1 = datetime.fromisoformat(parsed[-1])
        return abs((t1 - t0).total_seconds())
    except Exception:
        return None


# ─── Authentication-Results ──────────────────────────────────────────────────

def _parse_auth_results(headers: list) -> dict:
    results = {'spf': [], 'dkim': [], 'dmarc': [], 'arc': [], 'raw': []}
    for h in headers:
        results['raw'].append(h)
        for protocol in ('spf', 'dkim', 'dmarc', 'arc'):
            for m in re.finditer(
                rf'{protocol}\s*=\s*(\w+)([^;]*)', h, re.IGNORECASE
            ):
                entry = {'result': m.group(1).lower(), 'details': m.group(2).strip()}
                # Extract reason/problem
                reason_m = re.search(r'reason\s*=\s*"([^"]+)"', entry['details'], re.IGNORECASE)
                if reason_m:
                    entry['reason'] = reason_m.group(1)
                results[protocol].append(entry)
    return results


# ─── DKIM-Signature ──────────────────────────────────────────────────────────

def _parse_dkim_sigs(headers: list) -> list:
    sigs = []
    for h in headers:
        sig = {'raw': h}
        for tag in ('v', 'd', 's', 'a', 'c', 'bh', 'h', 'l', 't', 'x'):
            m = re.search(rf'(?:^|;)\s*{tag}\s*=\s*([^;]+)', h)
            if m:
                sig[tag] = m.group(1).strip()
        sigs.append(sig)
    return sigs


# ─── ARC ─────────────────────────────────────────────────────────────────────

def _parse_arc(msg) -> list:
    arc_sets: dict = {}
    for header_name in ('ARC-Seal', 'ARC-Message-Signature', 'ARC-Authentication-Results'):
        for h in (msg.get_all(header_name) or []):
            i_m = re.search(r'i\s*=\s*(\d+)', h)
            if i_m:
                i = int(i_m.group(1))
                arc_sets.setdefault(i, {})[header_name] = h
    return [{'instance': i, **v} for i, v in sorted(arc_sets.items())]


# ─── Spam scores ─────────────────────────────────────────────────────────────

def _parse_spam_scores(msg) -> dict:
    scores = {}
    for header in ('X-Spam-Score', 'X-Spam-Status', 'X-Spam-Level',
                   'X-MS-Exchange-Organization-SCL', 'X-Forefront-Antispam-Report',
                   'X-Google-DKIM-Signature', 'X-TM-AS-Result'):
        val = msg.get(header)
        if val:
            scores[header] = val
    return scores


# ─── Anomaly detection ───────────────────────────────────────────────────────

def _detect_anomalies(from_domain, return_domain, reply_domain,
                       received_chain, auth_results, spam_scores) -> list:
    issues = []

    # From / Return-Path mismatch
    if return_domain and from_domain and not _domains_align(from_domain, return_domain):
        issues.append({
            'severity': 'warning',
            'type': 'domain_mismatch',
            'message': f"From domain ({from_domain}) does not match Return-Path domain ({return_domain}) — possible spoofing indicator",
        })

    # From / Reply-To mismatch
    if reply_domain and from_domain and not _domains_align(from_domain, reply_domain):
        issues.append({
            'severity': 'warning',
            'type': 'reply_to_mismatch',
            'message': f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}) — common phishing technique",
        })

    # Auth failures
    for proto in ('spf', 'dkim', 'dmarc'):
        for entry in auth_results.get(proto, []):
            if entry.get('result') in ('fail', 'permerror', 'temperror', 'hardfail'):
                issues.append({
                    'severity': 'fail',
                    'type': f'{proto}_fail',
                    'message': f"{proto.upper()} authentication failed: {entry.get('result')} — {entry.get('reason', '')}".strip(' —'),
                })

    # Received hops without TLS
    non_tls = [h for h in received_chain if not h.get('tls') and h.get('from')]
    if non_tls:
        issues.append({
            'severity': 'warning',
            'type': 'unencrypted_hop',
            'message': f"{len(non_tls)} mail hop(s) transmitted without TLS encryption",
        })

    # High spam score
    scl = spam_scores.get('X-MS-Exchange-Organization-SCL')
    if scl and scl.strip().lstrip('-').isdigit() and int(scl) >= 6:
        issues.append({
            'severity': 'warning',
            'type': 'high_scl',
            'message': f"Microsoft SCL score is {scl} (≥6 = high spam confidence)",
        })

    return issues


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _extract_addr(header: str) -> str:
    m = re.search(r'<([^>]+)>', header)
    return m.group(1) if m else header.strip()


def _extract_domain(header: str) -> Optional[str]:
    addr = _extract_addr(header)
    if '@' in addr:
        return addr.split('@', 1)[1].lower().strip('>')
    return None


def _domains_align(d1: Optional[str], d2: Optional[str]) -> Optional[bool]:
    if not d1 or not d2:
        return None
    d1, d2 = d1.lower().rstrip('.'), d2.lower().rstrip('.')
    if d1 == d2:
        return True
    # Relaxed: check organisational domain (last two labels)
    org1 = '.'.join(d1.split('.')[-2:])
    org2 = '.'.join(d2.split('.')[-2:])
    return org1 == org2


# ─── URL extraction & analysis ────────────────────────────────────────────────

_URL_RE = re.compile(r'https?://[^\s<>"\'\]]+|www\.[^\s<>"\'\]]+', re.IGNORECASE)

_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'dlvr.it', 'is.gd', 'su.pr', 'tiny.cc', 'rb.gy', 'cutt.ly',
}

_SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.click', '.work', '.date', '.racing', '.download',
    '.loan', '.review', '.trade', '.webcam', '.accountant', '.stream',
}


def _extract_urls(msg) -> list:
    found = set()
    for name in msg.keys():
        val = msg.get(name, '')
        if val:
            for url in _URL_RE.findall(val):
                found.add(url.rstrip('.,;)>"\']'))
    return list(found)


def _analyse_urls(urls: list) -> dict:
    findings = []
    for url in urls:
        entry = {'url': url, 'flags': []}
        lower = url.lower()

        # IP address as host
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', lower):
            entry['flags'].append({'severity': 'fail', 'text': 'URL uses raw IP address instead of hostname'})

        # URL shortener
        for shortener in _SHORTENERS:
            if shortener in lower:
                entry['flags'].append({'severity': 'warning', 'text': f'URL shortener detected ({shortener}) — destination is hidden'})
                break

        # Suspicious TLD
        for tld in _SUSPICIOUS_TLDS:
            if lower.endswith(tld) or (tld + '/') in lower:
                entry['flags'].append({'severity': 'warning', 'text': f'Suspicious TLD ({tld})'})
                break

        # Mixed scheme in path (http inside https link)
        if 'https://' in lower and 'redirect' in lower and 'http://' in lower:
            entry['flags'].append({'severity': 'warning', 'text': 'Possible open redirect in URL'})

        findings.append(entry)

    flagged = [f for f in findings if f['flags']]
    return {
        'total': len(findings),
        'flagged_count': len(flagged),
        'flagged': flagged,
        'all_urls': findings,
    }


# ─── Timezone anomaly ─────────────────────────────────────────────────────────

def _check_timezone(date_str: str, received_chain: list) -> list:
    issues = []
    if not date_str:
        return issues
    try:
        msg_dt = parsedate_to_datetime(date_str)
        now = datetime.now(timezone.utc)
        msg_utc = msg_dt.astimezone(timezone.utc)
        diff_secs = (msg_utc - now).total_seconds()

        if diff_secs > 3600:
            issues.append({
                'severity': 'warning',
                'type': 'future_date',
                'message': f"Date header is {int(diff_secs/3600)}h in the future — possible clock skew or header forgery",
            })
        elif diff_secs < -7 * 86400:
            issues.append({
                'severity': 'warning',
                'type': 'stale_date',
                'message': "Date header is more than 7 days old — possible delayed delivery or header manipulation",
            })

        if msg_dt.tzinfo:
            offset_h = msg_dt.utcoffset().total_seconds() / 3600
            # Valid half-hour offsets: 5.5, 5.75, 6.5, 9.5, 10.5, 3.5, 4.5 etc.
            valid_halves = {x / 2 for x in range(-26, 30)}
            if offset_h not in valid_halves:
                issues.append({
                    'severity': 'info',
                    'type': 'unusual_timezone',
                    'message': f"Date header timezone UTC{'+' if offset_h >= 0 else ''}{offset_h} is non-standard",
                })

        # Cross-check with first Received header timestamp
        if received_chain and received_chain[0].get('timestamp_parsed'):
            try:
                first_hop = datetime.fromisoformat(received_chain[0]['timestamp_parsed'])
                skew = abs((first_hop.astimezone(timezone.utc) - msg_utc).total_seconds())
                if skew > 3600:
                    issues.append({
                        'severity': 'info',
                        'type': 'timestamp_skew',
                        'message': f"Date header differs from first Received timestamp by {int(skew/60)} minutes",
                    })
            except Exception:
                pass
    except Exception:
        pass
    return issues
