import asyncio
import dns.resolver

DNSBL = [
    ('zen.spamhaus.org',          'Spamhaus ZEN'),
    ('sbl.spamhaus.org',          'Spamhaus SBL'),
    ('xbl.spamhaus.org',          'Spamhaus XBL'),
    ('pbl.spamhaus.org',          'Spamhaus PBL'),
    ('bl.spamcop.net',            'SpamCop'),
    ('dnsbl.sorbs.net',           'SORBS Combined'),
    ('spam.dnsbl.sorbs.net',      'SORBS Spam'),
    ('b.barracudacentral.org',    'Barracuda'),
    ('cbl.abuseat.org',           'Composite Blocking List'),
    ('psbl.surriel.com',          'PSBL'),
    ('dnsbl-1.uceprotect.net',    'UCEProtect L1'),
    ('dnsbl-2.uceprotect.net',    'UCEProtect L2'),
    ('dnsbl.spfbl.net',           'SPFBL'),
    ('ubl.unsubscore.com',        'Lashback UBL'),
    ('bl.mailspike.net',          'Mailspike'),
    ('ix.dnsbl.manitu.net',       'iX Manitu'),
    ('rbl.trendmicro.com',        'TrendMicro ERS'),
    ('dbl.trendmicro.com',        'TrendMicro DBL'),
    ('0spam.fusionzero.com',      '0spam'),
    ('db.wpbl.info',              'WPBL'),
    ('bl.blocklist.de',           'Blocklist.de'),
    ('spam.rbl.msrbl.net',        'MSRBL Spam'),
    ('phishing.rbl.msrbl.net',    'MSRBL Phishing'),
]


def _reverse_ip(ip: str) -> str:
    return '.'.join(reversed(ip.split('.')))


async def check_blacklists(ips: list) -> dict:
    if not ips:
        return {'status': 'error', 'error': 'No IPs to check', 'listed': [], 'listed_count': 0, 'ips_checked': []}

    check_ips = ips[:3]
    tasks = [
        asyncio.get_event_loop().run_in_executor(None, _check_one, ip, bl, name)
        for ip in check_ips
        for bl, name in DNSBL
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    results = [r for r in results if isinstance(r, dict)]

    listed = [r for r in results if r.get('listed')]
    return {
        'status': 'ok',
        'listed_count': len(listed),
        'clean_count': len(results) - len(listed),
        'listed': listed,
        'ips_checked': check_ips,
        'lists_checked': len(DNSBL),
    }


def _check_one(ip: str, dnsbl: str, name: str) -> dict:
    r = dns.resolver.Resolver()
    r.timeout = 3
    r.lifetime = 5
    lookup = f'{_reverse_ip(ip)}.{dnsbl}'
    try:
        answers = r.resolve(lookup, 'A')
        codes = [str(a) for a in answers]
        reason = None
        try:
            for rd in r.resolve(lookup, 'TXT'):
                reason = ''.join(s.decode('utf-8', errors='replace') for s in rd.strings)
                break
        except Exception:
            pass
        return {'ip': ip, 'dnsbl': dnsbl, 'name': name, 'listed': True, 'return_codes': codes, 'reason': reason}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {'ip': ip, 'dnsbl': dnsbl, 'name': name, 'listed': False}
    except Exception as e:
        return {'ip': ip, 'dnsbl': dnsbl, 'name': name, 'listed': False, 'error': str(e)}
