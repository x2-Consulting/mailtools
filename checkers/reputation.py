import asyncio
import json
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError


async def check_whois(domain: str) -> dict:
    def _run():
        result = {}

        # ── RDAP (primary) ────────────────────────────────────────────────
        try:
            data = _rdap_domain(domain)
            created = expires = updated = None
            for event in data.get('events', []):
                action = event.get('eventAction', '').lower()
                date = event.get('eventDate', '')
                if action == 'registration':
                    created = date
                elif action == 'expiration':
                    expires = date
                elif action in ('last changed', 'last update of rdap database'):
                    updated = date

            registrar = _extract_entity_name(data, 'registrar')
            status_flags = data.get('status', [])
            nameservers = [ns.get('ldhName', '').lower() for ns in data.get('nameservers', [])]
            dnssec = 'signedDelegation' in status_flags or any('dnssec' in s.lower() for s in status_flags)

            result = {
                'registrar': registrar,
                'created': created,
                'expires': expires,
                'updated': updated,
                'status_flags': status_flags,
                'nameservers': nameservers,
                'dnssec': dnssec,
                'source': 'RDAP',
            }
        except Exception as rdap_err:
            result['rdap_error'] = str(rdap_err)

        # ── python-whois (supplement / fallback) ─────────────────────────
        try:
            import whois as pywhois
            w = pywhois.whois(domain)
            def _first(v):
                if isinstance(v, list):
                    return str(v[0]) if v else None
                return str(v) if v else None

            whois_data = {
                'registrar':    w.registrar or result.get('registrar'),
                'created':      result.get('created') or _first(w.creation_date),
                'expires':      result.get('expires') or _first(w.expiration_date),
                'updated':      result.get('updated') or _first(w.updated_date),
                'nameservers':  result.get('nameservers') or
                                ([ns.lower() for ns in (w.name_servers or [])]),
                'dnssec':       result.get('dnssec') or bool(w.dnssec and str(w.dnssec).lower() not in ('unsigned', 'none', 'false')),
                'registrant':   getattr(w, 'name', None) or getattr(w, 'org', None),
                'registrant_country': getattr(w, 'country', None),
                'abuse_email':  _first(w.emails) if w.emails else None,
                'source':       'RDAP+WHOIS' if not result.get('rdap_error') else 'WHOIS',
            }
            # Fill in anything RDAP missed
            for k, v in whois_data.items():
                if v is not None:
                    result[k] = v
        except Exception:
            pass  # python-whois failure is non-fatal

        if not result or (result.get('rdap_error') and 'source' not in result):
            return {'status': 'error', 'error': result.get('rdap_error', 'All WHOIS lookups failed'), 'domain': domain}

        # ── Compute age/expiry metrics ────────────────────────────────────
        domain_age_days = None
        created = result.get('created')
        if created:
            try:
                dt = datetime.fromisoformat(str(created).replace('Z', '+00:00').replace(' ', 'T').split('.')[0])
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                domain_age_days = (datetime.now(timezone.utc) - dt).days
            except Exception:
                pass

        days_to_expiry = None
        expires = result.get('expires')
        if expires:
            try:
                exp_dt = datetime.fromisoformat(str(expires).replace('Z', '+00:00').replace(' ', 'T').split('.')[0])
                if exp_dt.tzinfo is None:
                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                days_to_expiry = (exp_dt - datetime.now(timezone.utc)).days
            except Exception:
                pass

        warnings = []
        if domain_age_days is not None and domain_age_days < 30:
            warnings.append(f'Domain is only {domain_age_days} days old — very new domains score poorly with spam filters')
        elif domain_age_days is not None and domain_age_days < 180:
            warnings.append(f'Domain is {domain_age_days} days old — under 6 months old increases spam risk')
        if days_to_expiry is not None and days_to_expiry < 30:
            warnings.append(f'Domain expires in {days_to_expiry} day(s) — renew immediately!')
        elif days_to_expiry is not None and days_to_expiry < 90:
            warnings.append(f'Domain expires in {days_to_expiry} days — consider renewing soon')
        if result.get('dnssec') is False:
            warnings.append('DNSSEC not enabled — domain is vulnerable to DNS cache poisoning')

        return {
            'status': 'ok',
            'domain': domain,
            'registrar': result.get('registrar'),
            'created': result.get('created'),
            'expires': result.get('expires'),
            'updated': result.get('updated'),
            'domain_age_days': domain_age_days,
            'days_to_expiry': days_to_expiry,
            'status_flags': result.get('status_flags', []),
            'nameservers': result.get('nameservers', []),
            'dnssec': result.get('dnssec', False),
            'registrant': result.get('registrant'),
            'registrant_country': result.get('registrant_country'),
            'abuse_email': result.get('abuse_email'),
            'source': result.get('source', 'RDAP'),
            'warnings': warnings,
        }

    return await asyncio.get_event_loop().run_in_executor(None, _run)


async def check_ip_reputation(ips: list) -> dict:
    def _run():
        if not ips:
            return {'status': 'ok', 'results': []}

        results = []
        checked = list(dict.fromkeys(ips[:5]))  # dedupe, max 5

        # ── ip-api.com batch (primary — richer data) ──────────────────────
        try:
            payload = json.dumps([
                {'query': ip, 'fields': 'status,message,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,query'}
                for ip in checked
            ]).encode('utf-8')
            req = Request('http://ip-api.com/batch?fields=status,message,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,query',
                          data=payload,
                          headers={'Content-Type': 'application/json', 'User-Agent': 'MailTool/1.0'})
            with urlopen(req, timeout=10) as resp:
                batch = json.loads(resp.read().decode())

            for entry in batch:
                ip = entry.get('query', '')
                if entry.get('status') == 'success':
                    asn = entry.get('as', '')  # e.g. "AS15169 Google LLC"
                    results.append({
                        'ip': ip,
                        'status': 'ok',
                        'org_name': entry.get('org') or entry.get('isp') or '',
                        'isp': entry.get('isp', ''),
                        'asn': asn,
                        'country': entry.get('country', ''),
                        'country_code': entry.get('countryCode', ''),
                        'region': entry.get('regionName', ''),
                        'city': entry.get('city', ''),
                        'is_proxy': entry.get('proxy', False),
                        'is_hosting': entry.get('hosting', False),
                        'source': 'ip-api.com',
                    })
                else:
                    results.append({'ip': ip, 'status': 'error', 'error': entry.get('message', 'Lookup failed')})

        except Exception:
            # Fallback to RDAP for each IP
            for ip in checked:
                try:
                    data = _rdap_ip(ip)
                    if not data:
                        results.append({'ip': ip, 'status': 'error', 'error': 'RDAP lookup failed'})
                        continue

                    country = data.get('country', '')
                    org_name = (_extract_entity_name(data, 'registrant') or
                                _extract_entity_name(data, 'administrative') or
                                data.get('name', ''))

                    abuse_email = abuse_phone = None
                    for entity in data.get('entities', []):
                        if 'abuse' in entity.get('roles', []):
                            vcard = entity.get('vcardArray', [])
                            if vcard and len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == 'email' and not abuse_email:
                                        abuse_email = item[3]
                                    elif item[0] == 'tel' and not abuse_phone:
                                        abuse_phone = item[3]

                    cidr = None
                    for c in data.get('cidr0_cidrs', []):
                        prefix = c.get('v4prefix') or c.get('v6prefix', '')
                        length = c.get('length', '')
                        if prefix:
                            cidr = f'{prefix}/{length}'
                            break
                    if not cidr and '/' in data.get('handle', ''):
                        cidr = data['handle']

                    results.append({
                        'ip': ip,
                        'status': 'ok',
                        'org_name': org_name,
                        'country': country,
                        'cidr': cidr,
                        'abuse_email': abuse_email,
                        'abuse_phone': abuse_phone,
                        'source': 'RDAP',
                    })
                except Exception as e:
                    results.append({'ip': ip, 'status': 'error', 'error': str(e)})

        return {'status': 'ok' if results else 'error', 'results': results}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


_RDAP_DOMAIN_URLS = [
    'https://rdap.org/domain/{domain}',
    'https://rdap.iana.org/domain/{domain}',
]


def _rdap_domain(domain: str) -> dict:
    last_err = None
    for url_tpl in _RDAP_DOMAIN_URLS:
        url = url_tpl.format(domain=domain)
        try:
            req = Request(url, headers={'Accept': 'application/rdap+json', 'User-Agent': 'MailTool/1.0'})
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                if data:
                    return data
        except Exception as e:
            last_err = e
            continue
    raise Exception(f'RDAP lookup failed for {domain}: {last_err}')


def _rdap_ip(ip: str) -> dict:
    try:
        req = Request(f'https://rdap.org/ip/{ip}',
                      headers={'Accept': 'application/rdap+json', 'User-Agent': 'MailTool/1.0'})
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


def _extract_entity_name(data: dict, role: str) -> str:
    for entity in data.get('entities', []):
        if role in entity.get('roles', []):
            vcard = entity.get('vcardArray', [])
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == 'fn':
                        return item[3]
    return ''
