import asyncio
import socket
import dns.resolver
import dns.reversename
from typing import Optional
from checkers.utils import make_resolver

PROVIDER_SELECTORS = {
    'google': ['google', 'google2', 'googlemail'],
    'gmail': ['google', 'google2', 'googlemail'],
    'outlook': ['selector1', 'selector2'],
    'microsoft': ['selector1', 'selector2'],
    'office365': ['selector1', 'selector2'],
    'protection.outlook': ['selector1', 'selector2'],
    'amazonses': ['amazonses'],
    'ses.amazonaws': ['amazonses'],
    'mailchimp': ['k1', 'k2', 'k3'],
    'mandrill': ['k1', 'mandrill'],
    'sendgrid': ['s1', 's2', 'smtpapi', 'sendgrid'],
    'mimecast': ['mc', 'mc1', 'mc2', 'mimecast'],
    'proofpoint': ['pp1', 'pp2', 'proofpoint'],
    'pphosted': ['pp1', 'pp2'],
    'mailjet': ['mailjet', 'mj'],
    'postmarkapp': ['pm', 'pm1', 'pm2'],
    'zendesk': ['zendesk1', 'zendesk2'],
    'salesforce': ['sfmc', 'et'],
    'exacttarget': ['et', 'sfmc'],
    'sparkpost': ['scph', 'sp1'],
    'messagelabs': ['ml', 'mls'],
    'symantec': ['ml', 'mls'],
    'barracuda': ['bfi'],
    'trendmicro': ['tm', 'trendmicro'],
    'sophos': ['sophos'],
    'zoho': ['zoho', 'zmail'],
    'fastmail': ['fm1', 'fm2', 'fm3'],
    'mailgun': ['mailo', 'mg', 'pic'],
    'sendinblue': ['mail', 'smtp-relay'],
    'brevo': ['mail', 'smtp-relay'],
}

COMMON_SELECTORS = [
    'default', 'mail', 'dkim', 'email', 'smtp', 'mx',
    'selector1', 'selector2', 'selector3',
    'google', 'google2', 'googlemail',
    'k1', 'k2', 'k3',
    's1', 's2', 'smtpapi',
    'pm', 'pm1', 'pm2',
    'mc', 'mc1',
    'amazonses',
    'mandrill',
    'protonmail', 'proton',
    'zoho', 'zmail',
    'pp1', 'pp2',
    'fm1', 'fm2',
    'mj', 'mailjet',
    'mg', 'mailgun',
    'sp1', 'scph',
    '20161025', '20210112', '20230601',
    'dkim1', 'dkim2',
    'key1', 'key2',
    'sig1', 'sig2',
]


def _resolver():
    return make_resolver()


def _txt_strings(rdata) -> str:
    return ''.join(s.decode('utf-8', errors='replace') for s in rdata.strings)


# ─── MX ──────────────────────────────────────────────────────────────────────

async def check_mx(domain: str) -> dict:
    def _run():
        r = _resolver()
        try:
            answers = r.resolve(domain, 'MX')
            records = []
            for rdata in sorted(answers, key=lambda x: x.preference):
                host = str(rdata.exchange).rstrip('.')
                ip = None
                try:
                    a_ans = r.resolve(host, 'A')
                    ip = str(a_ans[0])
                except Exception:
                    pass
                ptr = None
                if ip:
                    try:
                        rev = dns.reversename.from_address(ip)
                        ptr_ans = r.resolve(rev, 'PTR')
                        ptr = str(ptr_ans[0]).rstrip('.')
                    except Exception:
                        pass
                records.append({'priority': rdata.preference, 'host': host, 'ip': ip, 'ptr': ptr})
            return {'status': 'ok', 'records': records}
        except dns.resolver.NXDOMAIN:
            return {'status': 'error', 'error': 'Domain does not exist', 'records': []}
        except dns.resolver.NoAnswer:
            return {'status': 'missing', 'error': 'No MX records found', 'records': []}
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'records': []}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


# ─── SPF ─────────────────────────────────────────────────────────────────────

async def check_spf(domain: str) -> dict:
    def _run():
        r = _resolver()
        try:
            answers = r.resolve(domain, 'TXT')
            spf_records = [_txt_strings(rd) for rd in answers if _txt_strings(rd).startswith('v=spf1')]
            if not spf_records:
                return {'status': 'missing', 'error': 'No SPF record found', 'record': None, 'parsed': None}
            if len(spf_records) > 1:
                return {
                    'status': 'warning',
                    'warning': 'Multiple SPF records found — this is invalid per RFC 7208',
                    'records': spf_records,
                    'record': spf_records[0],
                    'parsed': _parse_spf(spf_records[0]),
                }
            record = spf_records[0]
            return {'status': 'ok', 'record': record, 'parsed': _parse_spf(record)}
        except dns.resolver.NXDOMAIN:
            return {'status': 'error', 'error': 'Domain does not exist', 'record': None, 'parsed': None}
        except dns.resolver.NoAnswer:
            return {'status': 'missing', 'error': 'No SPF record found', 'record': None, 'parsed': None}
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'record': None, 'parsed': None}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _parse_spf(record: str) -> dict:
    parts = record.split()
    parsed = {
        'version': None,
        'mechanisms': [],
        'includes': [],
        'ip4': [],
        'ip6': [],
        'a_records': [],
        'mx_records': [],
        'all_mechanism': None,
        'redirect': None,
        'lookup_count': 0,
        'warnings': [],
    }

    for part in parts:
        lp = part.lower()
        if lp.startswith('v='):
            parsed['version'] = part[2:]
        elif lp in ('all', '+all', '-all', '~all', '?all'):
            parsed['all_mechanism'] = part
        elif 'include:' in lp:
            parsed['includes'].append(part.split(':', 1)[1])
            parsed['lookup_count'] += 1
        elif lp.startswith('ip4:'):
            parsed['ip4'].append(part[4:])
        elif lp.startswith('ip6:'):
            parsed['ip6'].append(part[4:])
        elif 'redirect=' in lp:
            parsed['redirect'] = part.split('=', 1)[1]
            parsed['lookup_count'] += 1
        elif lp in ('a', '+a', '-a', '~a', '?a') or lp.startswith(('a:', 'a/')):
            parsed['a_records'].append(part)
            parsed['lookup_count'] += 1
        elif lp in ('mx', '+mx', '-mx', '~mx', '?mx') or lp.startswith(('mx:', 'mx/')):
            parsed['mx_records'].append(part)
            parsed['lookup_count'] += 1
        elif lp == 'ptr' or lp.startswith('ptr:'):
            parsed['lookup_count'] += 1
        elif lp.startswith('exists:'):
            parsed['lookup_count'] += 1
        parsed['mechanisms'].append(part)

    if parsed['lookup_count'] > 10:
        parsed['warnings'].append(f"Too many DNS lookups ({parsed['lookup_count']}/10) — may cause SPF permerror")
    if not parsed['all_mechanism']:
        parsed['warnings'].append("No 'all' mechanism — behaviour undefined for non-matching senders")
    if parsed['all_mechanism'] in ('+all', 'all'):
        parsed['warnings'].append("'+all' allows any sender — effectively disables SPF protection")
    if parsed['all_mechanism'] == '~all':
        parsed['warnings'].append("'~all' (softfail) — consider upgrading to '-all' to reject unauthorised senders")

    return parsed


# ─── DMARC ───────────────────────────────────────────────────────────────────

async def check_dmarc(domain: str) -> dict:
    def _run():
        r = _resolver()
        try:
            answers = r.resolve(f'_dmarc.{domain}', 'TXT')
            records = [_txt_strings(rd) for rd in answers if _txt_strings(rd).startswith('v=DMARC1')]
            if not records:
                return {'status': 'missing', 'error': 'No DMARC record found', 'record': None, 'parsed': None}
            record = records[0]
            parsed = _parse_dmarc(record)
            return {
                'status': 'ok',
                'record': record,
                'parsed': parsed,
                'policy': parsed.get('p', 'none'),
                'subdomain_policy': parsed.get('sp'),
            }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {'status': 'missing', 'error': 'No DMARC record found', 'record': None, 'parsed': None}
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'record': None, 'parsed': None}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _parse_dmarc(record: str) -> dict:
    tags = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip()] = v.strip()

    warnings = []
    if tags.get('p') == 'none':
        warnings.append("Policy is 'none' — emails are monitored but never rejected or quarantined")
    if tags.get('p') == 'quarantine':
        warnings.append("Policy is 'quarantine' — consider upgrading to 'reject' for full protection")
    if not tags.get('rua'):
        warnings.append("No aggregate report URI (rua) — you won't receive DMARC reports")
    if not tags.get('ruf'):
        warnings.append("No forensic report URI (ruf) — failure reports disabled")
    pct = int(tags.get('pct', 100))
    if pct < 100:
        warnings.append(f"Policy only applied to {pct}% of messages (pct={pct})")
    if tags.get('adkim') == 'r':
        warnings.append("DKIM alignment is 'relaxed' — subdomain DKIM signatures pass")
    if tags.get('aspf') == 'r':
        warnings.append("SPF alignment is 'relaxed' — subdomain SPF passes")

    tags['warnings'] = warnings
    return tags


# ─── DKIM ────────────────────────────────────────────────────────────────────

async def check_dkim(domain: str, custom_selectors: list = None, mx_records: list = None) -> dict:
    def _run():
        r = _resolver()
        selectors = set(COMMON_SELECTORS)

        # Infer selectors from MX provider
        if mx_records:
            for mx in mx_records:
                host = mx.get('host', '').lower()
                for provider, sels in PROVIDER_SELECTORS.items():
                    if provider in host:
                        selectors.update(sels)

        # Check _domainkeys TXT for hints
        try:
            answers = r.resolve(f'_domainkeys.{domain}', 'TXT')
            for rdata in answers:
                txt = _txt_strings(rdata)
                for token in txt.replace(';', ' ').replace(',', ' ').split():
                    if token and len(token) < 64:
                        selectors.add(token.strip())
        except Exception:
            pass

        if custom_selectors:
            selectors.update(s.strip() for s in custom_selectors if s.strip())

        found = []
        for selector in selectors:
            dkim_host = f'{selector}._domainkey.{domain}'
            try:
                answers = r.resolve(dkim_host, 'TXT')
                for rdata in answers:
                    txt = _txt_strings(rdata)
                    if 'p=' in txt or 'k=' in txt:
                        found.append({
                            'selector': selector,
                            'record': txt,
                            'parsed': _parse_dkim(txt),
                            'fqdn': dkim_host,
                        })
                        break
            except Exception:
                pass

        return {
            'status': 'ok' if found else 'missing',
            'found_selectors': found,
            'selectors_checked': len(selectors),
            'auto_detected': True,
            'error': None if found else 'No DKIM records found with known selectors',
        }

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _parse_dkim(record: str) -> dict:
    tags = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip()] = v.strip()

    p = tags.get('p', '')
    key_type = tags.get('k', 'rsa')
    warnings = []

    if not p:
        warnings.append("Key is revoked (empty p= tag)")
    elif key_type == 'rsa' and len(p) < 216:
        warnings.append("RSA key appears to be 1024-bit or less — upgrade to 2048-bit recommended")

    tags['key_type'] = key_type
    tags['key_revoked'] = not p
    tags['key_length_hint'] = len(p)
    tags['warnings'] = warnings
    return tags


# ─── BIMI ────────────────────────────────────────────────────────────────────

async def check_bimi(domain: str) -> dict:
    def _run():
        r = _resolver()
        for prefix in ['default', 'selector1']:
            try:
                answers = r.resolve(f'{prefix}._bimi.{domain}', 'TXT')
                for rdata in answers:
                    txt = _txt_strings(rdata)
                    if txt.startswith('v=BIMI1'):
                        parsed = _parse_bimi(txt)
                        return {
                            'status': 'ok',
                            'record': txt,
                            'selector': prefix,
                            'parsed': parsed,
                            'logo_url': parsed.get('l'),
                            'vmc_url': parsed.get('a'),
                        }
            except Exception:
                pass
        return {'status': 'missing', 'error': 'No BIMI record found', 'record': None, 'parsed': None}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _parse_bimi(record: str) -> dict:
    tags = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip()] = v.strip()

    warnings = []
    if not tags.get('l'):
        warnings.append("No logo URL (l=) — required for BIMI display")
    else:
        if not tags['l'].lower().endswith('.svg'):
            warnings.append("Logo URL should point to an SVG file (Tiny PS profile)")
    if not tags.get('a'):
        warnings.append("No VMC certificate URL (a=) — required for Gmail and Apple Mail logo display")

    tags['warnings'] = warnings
    return tags


# ─── SPF include chain expansion ─────────────────────────────────────────────

async def expand_spf_chain(domain: str) -> dict:
    def _run():
        node = _expand_recursive(domain, 0, set())
        return {
            'status': 'ok' if node.get('record') else 'missing',
            'tree': node,
            'total_lookups': node.get('lookups', 0),
            'total_ip4': len(node.get('all_ip4', [])),
            'total_ip6': len(node.get('all_ip6', [])),
            'all_ip4': node.get('all_ip4', []),
            'all_ip6': node.get('all_ip6', []),
        }
    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _expand_recursive(domain: str, depth: int, visited: set) -> dict:
    node = {
        'domain': domain, 'record': None,
        'direct_ip4': [], 'direct_ip6': [],
        'all_ip4': [], 'all_ip6': [],
        'all_mechanism': None, 'includes': [],
        'lookups': 0, 'error': None,
    }
    if domain in visited:
        node['error'] = 'Circular reference'; return node
    if depth > 6:
        node['error'] = 'Max recursion depth exceeded'; return node

    visited.add(domain)
    r = _resolver()
    try:
        answers = r.resolve(domain, 'TXT')
        spf_records = [_txt_strings(rd) for rd in answers if _txt_strings(rd).startswith('v=spf1')]
    except Exception as e:
        node['error'] = str(e); node['lookups'] = 1; return node

    if not spf_records:
        node['error'] = 'No SPF record'; node['lookups'] = 1; return node

    record = spf_records[0]
    parsed = _parse_spf(record)
    node['record'] = record
    node['direct_ip4'] = list(parsed.get('ip4', []))
    node['direct_ip6'] = list(parsed.get('ip6', []))
    node['all_ip4'] = list(parsed.get('ip4', []))
    node['all_ip6'] = list(parsed.get('ip6', []))
    node['all_mechanism'] = parsed.get('all_mechanism')
    node['lookups'] = 1 + len(parsed.get('a_records', [])) + len(parsed.get('mx_records', []))

    for include_domain in parsed.get('includes', []):
        child = _expand_recursive(include_domain, depth + 1, visited)
        node['includes'].append(child)
        node['lookups'] += child.get('lookups', 0)
        node['all_ip4'].extend(child.get('all_ip4', []))
        node['all_ip6'].extend(child.get('all_ip6', []))

    if parsed.get('redirect'):
        child = _expand_recursive(parsed['redirect'], depth + 1, visited)
        child['_is_redirect'] = True
        node['includes'].append(child)
        node['lookups'] += child.get('lookups', 0)
        node['all_ip4'].extend(child.get('all_ip4', []))
        node['all_ip6'].extend(child.get('all_ip6', []))

    return node
