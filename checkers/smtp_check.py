import asyncio
import smtplib
import ssl
import socket
import time
from typing import Optional

PORTS = [25, 587, 465]


async def check_smtp(mx_hosts: list) -> dict:
    if not mx_hosts:
        return {'status': 'error', 'error': 'No MX hosts to test', 'results': []}

    hosts = mx_hosts[:2]
    tasks = [
        asyncio.get_event_loop().run_in_executor(None, _test_port, host, port)
        for host in hosts
        for port in PORTS
    ]
    raw = await asyncio.gather(*tasks, return_exceptions=True)

    results = [r for r in raw if isinstance(r, dict)]
    return {
        'status': 'ok' if any(r['connected'] for r in results) else 'error',
        'results': results,
    }


def _test_port(host: str, port: int) -> dict:
    result = {
        'host': host,
        'port': port,
        'connected': False,
        'banner': None,
        'starttls_available': None,
        'tls_established': False,
        'tls_version': None,
        'cipher': None,
        'cert_cn': None,
        'cert_expiry': None,
        'ehlo_features': [],
        'error': None,
        'latency_ms': None,
    }

    start = time.time()
    smtp = None
    try:
        if port == 465:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            smtp = smtplib.SMTP_SSL(host, port, context=ctx, timeout=10)
            result['tls_established'] = True
            _extract_tls(smtp, result)
        else:
            smtp = smtplib.SMTP(host, port, timeout=10)

        result['connected'] = True
        result['latency_ms'] = round((time.time() - start) * 1000)

        raw_banner = smtp.getwelcome()
        result['banner'] = raw_banner.decode('utf-8', errors='replace') if raw_banner else None

        smtp.ehlo('mailcheck.tool')
        result['ehlo_features'] = sorted(smtp.esmtp_features.keys())

        if port in (25, 587):
            has_starttls = smtp.has_extn('starttls')
            result['starttls_available'] = has_starttls
            if has_starttls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                smtp.starttls(context=ctx)
                smtp.ehlo('mailcheck.tool')
                result['tls_established'] = True
                _extract_tls(smtp, result)

        smtp.quit()

    except smtplib.SMTPConnectError as e:
        result['error'] = f'Connection refused or failed: {e}'
    except smtplib.SMTPServerDisconnected as e:
        result['error'] = f'Server disconnected: {e}'
    except socket.timeout:
        result['error'] = 'Connection timed out'
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
    except OSError as e:
        result['error'] = str(e)
    except Exception as e:
        result['error'] = str(e)
    finally:
        if smtp:
            try:
                smtp.close()
            except Exception:
                pass

    return result


def _extract_tls(smtp, result: dict):
    try:
        sock = smtp.sock
        if hasattr(sock, 'version'):
            result['tls_version'] = sock.version()
        if hasattr(sock, 'cipher'):
            c = sock.cipher()
            result['cipher'] = c[0] if c else None
        if hasattr(sock, 'getpeercert'):
            cert = sock.getpeercert()
            if cert:
                for field in cert.get('subject', []):
                    for k, v in field:
                        if k == 'commonName':
                            result['cert_cn'] = v
                result['cert_expiry'] = cert.get('notAfter')
    except Exception:
        pass
