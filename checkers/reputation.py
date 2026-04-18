import asyncio
import json
from datetime import datetime, timezone
from urllib.request import urlopen, Request
from urllib.error import URLError


async def check_whois(domain: str) -> dict:
    def _run():
        try:
            data = _rdap_domain(domain)
            if not data:
                return {'status': 'error', 'error': 'RDAP lookup failed', 'domain': domain}

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
            nameservers = [ns.get('ldhName', '') for ns in data.get('nameservers', [])]

            domain_age_days = None
            if created:
                try:
                    dt = datetime.fromisoformat(created.replace('Z', '+00:00'))
                    domain_age_days = (datetime.now(timezone.utc) - dt).days
                except Exception:
                    pass

            days_to_expiry = None
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires.replace('Z', '+00:00'))
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

            return {
                'status': 'ok',
                'domain': domain,
                'registrar': registrar,
                'created': created,
                'expires': expires,
                'updated': updated,
                'domain_age_days': domain_age_days,
                'days_to_expiry': days_to_expiry,
                'status_flags': status_flags,
                'nameservers': nameservers,
                'warnings': warnings,
            }
        except Exception as e:
            return {'status': 'error', 'error': str(e), 'domain': domain}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


async def check_ip_reputation(ips: list) -> dict:
    def _run():
        results = []
        for ip in ips[:3]:
            try:
                data = _rdap_ip(ip)
                if not data:
                    results.append({'ip': ip, 'status': 'error', 'error': 'RDAP lookup failed'})
                    continue

                country = data.get('country', '')
                org_name = _extract_entity_name(data, 'registrant') or \
                           _extract_entity_name(data, 'administrative') or \
                           data.get('name', '')

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
                })
            except Exception as e:
                results.append({'ip': ip, 'status': 'error', 'error': str(e)})

        return {'status': 'ok' if results else 'error', 'results': results}

    return await asyncio.get_event_loop().run_in_executor(None, _run)


def _rdap_domain(domain: str) -> dict:
    try:
        req = Request(f'https://rdap.org/domain/{domain}',
                      headers={'Accept': 'application/rdap+json', 'User-Agent': 'MailTool/1.0'})
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode())
    except Exception:
        return {}


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
