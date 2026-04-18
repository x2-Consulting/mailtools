import asyncio
import ssl
import dns.resolver
from urllib.request import urlopen, Request
from urllib.error import URLError
from checkers.utils import make_resolver


def _resolver():
    return make_resolver()


def _txt(rdata) -> str:
    return ''.join(s.decode('utf-8', errors='replace') for s in rdata.strings)


# ─── MTA-STS ─────────────────────────────────────────────────────────────────

async def check_mta_sts(domain: str) -> dict:
    def _run():
        r = _resolver()

        # 1. DNS TXT record
        dns_record = None
        dns_id = None
        try:
            for rd in r.resolve(f'_mta-sts.{domain}', 'TXT'):
                txt = _txt(rd)
                if txt.startswith('v=STSv1'):
                    dns_record = txt
                    for part in txt.split(';'):
                        part = part.strip()
                        if part.startswith('id='):
                            dns_id = part[3:]
                    break
        except Exception:
            pass

        # 2. Fetch policy file
        policy_url = f'https://mta-sts.{domain}/.well-known/mta-sts.txt'
        policy = None
        cert_valid = None
        fetch_error = None

        try:
            req = Request(policy_url, headers={'User-Agent': 'MailTool/1.0'})
            with urlopen(req, timeout=10) as resp:
                policy = _parse_mta_sts_policy(resp.read().decode('utf-8', errors='replace'))
                cert_valid = True
        except ssl.SSLCertVerificationError:
            cert_valid = False
            fetch_error = 'TLS certificate invalid — policy served but cert cannot be verified'
            # Fetch anyway so we can still report the policy contents
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with urlopen(Request(policy_url), context=ctx, timeout=10) as resp:
                    policy = _parse_mta_sts_policy(resp.read().decode('utf-8', errors='replace'))
            except Exception:
                pass
        except URLError as e:
            fetch_error = f'Policy file not reachable: {e.reason}'
        except Exception as e:
            fetch_error = str(e)

        if not dns_record and not policy:
            return {'status': 'missing', 'error': 'No MTA-STS DNS record or policy file found',
                    'dns_record': None, 'policy': None}

        warnings = []
        if not dns_record:
            warnings.append('MTA-STS DNS TXT record (_mta-sts) missing')
        if not policy:
            warnings.append(f'Policy file not accessible: {fetch_error}')
        elif policy.get('mode') == 'testing':
            warnings.append("Mode is 'testing' — TLS enforced for reporting only, not rejected")
        elif policy.get('mode') == 'none':
            warnings.append("Mode is 'none' — MTA-STS is effectively disabled")
        if cert_valid is False:
            warnings.append('Policy served over HTTPS with an invalid certificate')

        enforcing = dns_record and policy and policy.get('mode') == 'enforce' and cert_valid
        return {
            'status': 'ok' if enforcing else 'warning' if (dns_record or policy) else 'missing',
            'dns_record': dns_record,
            'dns_id': dns_id,
            'policy': policy,
            'policy_url': policy_url,
            'cert_valid': cert_valid,
            'warnings': warnings,
        }

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _parse_mta_sts_policy(text: str) -> dict:
    policy = {}
    mx = []
    for line in text.strip().splitlines():
        line = line.strip()
        if ':' in line:
            k, v = line.split(':', 1)
            k, v = k.strip(), v.strip()
            if k == 'mx':
                mx.append(v)
            else:
                policy[k] = v
    policy['mx'] = mx
    return policy


# ─── TLS-RPT ─────────────────────────────────────────────────────────────────

async def check_tls_rpt(domain: str) -> dict:
    def _run():
        r = _resolver()
        try:
            for rd in r.resolve(f'_smtp._tls.{domain}', 'TXT'):
                txt = _txt(rd)
                if txt.startswith('v=TLSRPTv1'):
                    parsed = _parse_tls_rpt(txt)
                    return {'status': 'ok', 'record': txt, 'parsed': parsed, 'rua': parsed.get('rua')}
            return {'status': 'missing', 'error': 'No TLS-RPT record found', 'record': None}
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return {'status': 'missing', 'error': 'No TLS-RPT record found', 'record': None}
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'record': None}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _parse_tls_rpt(record: str) -> dict:
    tags = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip()] = v.strip()
    warnings = []
    if not tags.get('rua'):
        warnings.append('No report URI (rua) — TLS failure reports will not be received')
    tags['warnings'] = warnings
    return tags


# ─── DANE / TLSA ─────────────────────────────────────────────────────────────

async def check_dane(mx_records: list) -> dict:
    def _run():
        r = _resolver()
        results = []

        for mx in mx_records[:3]:
            host = mx.get('host', '')
            lookup = f'_25._tcp.{host}'
            try:
                records = []
                for rd in r.resolve(lookup, 'TLSA'):
                    records.append({
                        'usage':         rd.usage,
                        'selector':      rd.selector,
                        'mtype':         rd.mtype,
                        'cert_hex':      rd.cert.hex()[:64] + ('…' if len(rd.cert.hex()) > 64 else ''),
                        'usage_name':    {0:'PKIX-TA', 1:'PKIX-EE', 2:'DANE-TA', 3:'DANE-EE'}.get(rd.usage, str(rd.usage)),
                        'selector_name': {0:'Full Cert', 1:'SPKI'}.get(rd.selector, str(rd.selector)),
                        'mtype_name':    {0:'Full Match', 1:'SHA-256', 2:'SHA-512'}.get(rd.mtype, str(rd.mtype)),
                    })
                results.append({'host': host, 'status': 'ok', 'records': records, 'fqdn': lookup})
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                results.append({'host': host, 'status': 'missing', 'records': [], 'fqdn': lookup})
            except Exception as e:
                results.append({'host': host, 'status': 'error', 'error': str(e), 'records': [], 'fqdn': lookup})

        has_dane = any(r['status'] == 'ok' for r in results)
        return {
            'status': 'ok' if has_dane else 'missing',
            'results': results,
            'error': None if has_dane else 'No DANE/TLSA records found for MX hosts',
        }

    return await asyncio.get_event_loop().run_in_executor(None, _run)
