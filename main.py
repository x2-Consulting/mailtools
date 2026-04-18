import asyncio
import base64
from fastapi import FastAPI, Request, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional
import io

from checkers.dns_checks import check_mx, check_spf, check_dmarc, check_dkim, check_bimi, expand_spf_chain
from checkers.smtp_check import check_smtp, check_open_relay, check_catch_all
from checkers.blacklist import check_blacklists
from checkers.header_analyzer import analyze_headers
from checkers.mta_sts import check_mta_sts, check_tls_rpt, check_dane
from checkers.reputation import check_whois, check_ip_reputation
from report import build_pdf

app = FastAPI(title="MailTool")
app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")


class DomainRequest(BaseModel):
    domain: str
    dkim_selectors: list[str] = []


class HeaderRequest(BaseModel):
    headers: str


# ─── UI ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# ─── Full check ──────────────────────────────────────────────────────────────

@app.post("/check")
async def check_all(req: DomainRequest):
    domain = _clean(req.domain)
    if not domain:
        raise HTTPException(400, "Domain is required")

    mx = await check_mx(domain)
    mx_records = mx.get('records', [])
    mx_hosts = [r['host'] for r in mx_records]
    mx_ips = [r['ip'] for r in mx_records if r.get('ip')]

    (spf, dmarc, dkim, bimi,
     mta_sts, tls_rpt, dane,
     blacklist, smtp,
     open_relay, catch_all,
     whois, ip_rep, spf_chain) = await asyncio.gather(
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain, req.dkim_selectors, mx_records),
        check_bimi(domain),
        check_mta_sts(domain),
        check_tls_rpt(domain),
        check_dane(mx_records),
        check_blacklists(mx_ips),
        check_smtp(mx_hosts),
        check_open_relay(mx_hosts),
        check_catch_all(mx_hosts, domain),
        check_whois(domain),
        check_ip_reputation(mx_ips),
        expand_spf_chain(domain),
    )

    score = _calculate_score(mx, spf, dmarc, dkim, blacklist, open_relay)
    return {
        "domain": domain,
        "mx": mx,
        "spf": spf, "spf_chain": spf_chain,
        "dmarc": dmarc,
        "dkim": dkim,
        "bimi": bimi,
        "mta_sts": mta_sts, "tls_rpt": tls_rpt,
        "dane": dane,
        "blacklist": blacklist,
        "smtp": smtp,
        "open_relay": open_relay,
        "catch_all": catch_all,
        "whois": whois,
        "ip_reputation": ip_rep,
        "score": score,
    }


# ─── Individual checks ───────────────────────────────────────────────────────

@app.post("/check/mx")
async def api_mx(req: DomainRequest):
    return await check_mx(_clean(req.domain))

@app.post("/check/spf")
async def api_spf(req: DomainRequest):
    return await check_spf(_clean(req.domain))

@app.post("/check/spf-chain")
async def api_spf_chain(req: DomainRequest):
    return await expand_spf_chain(_clean(req.domain))

@app.post("/check/dmarc")
async def api_dmarc(req: DomainRequest):
    return await check_dmarc(_clean(req.domain))

@app.post("/check/dkim")
async def api_dkim(req: DomainRequest):
    domain = _clean(req.domain)
    mx = await check_mx(domain)
    return await check_dkim(domain, req.dkim_selectors, mx.get('records', []))

@app.post("/check/bimi")
async def api_bimi(req: DomainRequest):
    return await check_bimi(_clean(req.domain))

@app.post("/check/mta-sts")
async def api_mta_sts(req: DomainRequest):
    domain = _clean(req.domain)
    mta, tls = await asyncio.gather(check_mta_sts(domain), check_tls_rpt(domain))
    return {'mta_sts': mta, 'tls_rpt': tls}

@app.post("/check/dane")
async def api_dane(req: DomainRequest):
    mx = await check_mx(_clean(req.domain))
    return await check_dane(mx.get('records', []))

@app.post("/check/blacklist")
async def api_blacklist(req: DomainRequest):
    mx = await check_mx(_clean(req.domain))
    ips = [r['ip'] for r in mx.get('records', []) if r.get('ip')]
    return await check_blacklists(ips)

@app.post("/check/smtp")
async def api_smtp(req: DomainRequest):
    mx = await check_mx(_clean(req.domain))
    hosts = [r['host'] for r in mx.get('records', [])]
    return await check_smtp(hosts)

@app.post("/check/relay")
async def api_relay(req: DomainRequest):
    mx = await check_mx(_clean(req.domain))
    hosts = [r['host'] for r in mx.get('records', [])]
    return await check_open_relay(hosts)

@app.post("/check/catchall")
async def api_catchall(req: DomainRequest):
    domain = _clean(req.domain)
    mx = await check_mx(domain)
    hosts = [r['host'] for r in mx.get('records', [])]
    return await check_catch_all(hosts, domain)

@app.post("/check/whois")
async def api_whois(req: DomainRequest):
    return await check_whois(_clean(req.domain))

@app.post("/check/ip-reputation")
async def api_ip_rep(req: DomainRequest):
    mx = await check_mx(_clean(req.domain))
    ips = [r['ip'] for r in mx.get('records', []) if r.get('ip')]
    return await check_ip_reputation(ips)

@app.post("/check/headers")
async def api_headers(req: HeaderRequest):
    if not req.headers.strip():
        raise HTTPException(400, "Headers are required")
    return analyze_headers(req.headers)


# ─── BIMI SVG Converter ──────────────────────────────────────────────────────

@app.post("/tools/bimi-convert")
async def bimi_convert(file: UploadFile = File(...)):
    from checkers.bimi_converter import convert_to_bimi_svg
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(400, "File too large (max 5 MB)")
    result = convert_to_bimi_svg(content, file.filename or '')
    svg_b64 = base64.b64encode(result['svg']).decode() if result.get('svg') else None
    fname = (file.filename or 'logo').rsplit('.', 1)[0] + '_bimi.svg'
    return {
        'svg_b64': svg_b64,
        'filename': fname,
        'warnings': result['warnings'],
        'errors': result['errors'],
        'valid': result['valid'],
    }


# ─── PDF report ──────────────────────────────────────────────────────────────

@app.post("/report/pdf")
async def pdf_report(req: DomainRequest):
    domain = _clean(req.domain)
    if not domain:
        raise HTTPException(400, "Domain is required")

    mx = await check_mx(domain)
    mx_records = mx.get('records', [])
    mx_hosts = [r['host'] for r in mx_records]
    mx_ips = [r['ip'] for r in mx_records if r.get('ip')]

    (spf, dmarc, dkim, bimi,
     mta_sts, tls_rpt, dane,
     blacklist, smtp,
     open_relay, catch_all,
     whois, ip_rep, spf_chain) = await asyncio.gather(
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain, req.dkim_selectors, mx_records),
        check_bimi(domain),
        check_mta_sts(domain),
        check_tls_rpt(domain),
        check_dane(mx_records),
        check_blacklists(mx_ips),
        check_smtp(mx_hosts),
        check_open_relay(mx_hosts),
        check_catch_all(mx_hosts, domain),
        check_whois(domain),
        check_ip_reputation(mx_ips),
        expand_spf_chain(domain),
    )

    score = _calculate_score(mx, spf, dmarc, dkim, blacklist, open_relay)
    data = {
        "domain": domain,
        "mx": mx, "spf": spf, "spf_chain": spf_chain,
        "dmarc": dmarc, "dkim": dkim, "bimi": bimi,
        "mta_sts": mta_sts, "tls_rpt": tls_rpt,
        "dane": dane, "blacklist": blacklist,
        "smtp": smtp, "open_relay": open_relay, "catch_all": catch_all,
        "whois": whois, "ip_reputation": ip_rep,
        "score": score,
    }

    pdf_bytes = build_pdf(data)
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="mailcheck-{domain}.pdf"'},
    )


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _clean(domain: str) -> str:
    return (domain.strip().lower()
            .removeprefix("https://").removeprefix("http://")
            .rstrip("/"))


def _calculate_score(mx, spf, dmarc, dkim, blacklist, open_relay) -> dict:
    """
    Score is based exclusively on the four required areas (25 pts each = 100 total).

    Required:
      MX + Blacklists  25 pts  — can you receive mail, and are you blacklisted?
      SPF              25 pts  — is outbound mail authorised correctly?
      DMARC            25 pts  — is spoofing of your domain prevented?
      DKIM             25 pts  — is outbound mail cryptographically signed?

    Open relay is a critical security failure and deducts 25 pts regardless.

    Optional checks (BIMI, MTA-STS, DANE, TLS-RPT) are displayed separately
    and do not affect the score — they are enhancements, not requirements.
    """
    issues = []
    core = {}

    # ── MX + Blacklists (25 pts) ──────────────────────────────────────────
    mx_pts = 0
    if mx.get('records'):
        mx_pts = 25
        listed = blacklist.get('listed_count', 0)
        if listed:
            mx_pts = max(mx_pts - (listed * 5), 0)
            issues.append({'severity': 'fail', 'text': f'Listed on {listed} blacklist(s)'})
    else:
        issues.append({'severity': 'fail', 'text': 'No MX records found'})
    core['mx_blacklist'] = {'label': 'MX & Blacklists', 'score': mx_pts, 'max': 25}

    # ── SPF (25 pts) ──────────────────────────────────────────────────────
    spf_pts = 0
    spf_s = spf.get('status')
    if spf_s == 'missing':
        issues.append({'severity': 'fail', 'text': 'No SPF record'})
    elif spf_s == 'warning':
        spf_pts = 10
        issues.append({'severity': 'warning', 'text': 'Multiple SPF records — RFC violation'})
    elif spf_s == 'ok':
        parsed = spf.get('parsed') or {}
        mech = parsed.get('all_mechanism', '')
        if mech == '-all':
            spf_pts = 25
        elif mech == '~all':
            spf_pts = 18
            issues.append({'severity': 'warning', 'text': "SPF softfail (~all) — consider upgrading to -all"})
        elif mech in ('+all', 'all'):
            spf_pts = 3
            issues.append({'severity': 'fail', 'text': "SPF uses +all — any server on the internet is permitted to send as you"})
        else:
            spf_pts = 15
            issues.append({'severity': 'warning', 'text': "SPF has no 'all' mechanism — behaviour undefined for non-matching senders"})
        if parsed.get('lookup_count', 0) > 10:
            spf_pts = max(spf_pts - 5, 0)
            issues.append({'severity': 'warning', 'text': "SPF exceeds 10 DNS lookup limit — receiving servers may return permerror"})
    core['spf'] = {'label': 'SPF', 'score': spf_pts, 'max': 25}

    # ── DMARC (25 pts) ────────────────────────────────────────────────────
    dmarc_pts = 0
    dmarc_s = dmarc.get('status')
    if dmarc_s == 'missing':
        issues.append({'severity': 'fail', 'text': 'No DMARC record'})
    elif dmarc_s == 'ok':
        policy = dmarc.get('policy', 'none')
        if policy == 'reject':
            dmarc_pts = 25
        elif policy == 'quarantine':
            dmarc_pts = 18
            issues.append({'severity': 'warning', 'text': "DMARC policy is 'quarantine' — consider upgrading to 'reject'"})
        else:
            dmarc_pts = 8
            issues.append({'severity': 'warning', 'text': "DMARC policy is 'none' — domain spoofing is not prevented, monitoring only"})
    core['dmarc'] = {'label': 'DMARC', 'score': dmarc_pts, 'max': 25}

    # ── DKIM (25 pts) ─────────────────────────────────────────────────────
    dkim_pts = 0
    if dkim.get('found_selectors'):
        dkim_pts = 25
        for sel in dkim['found_selectors']:
            if sel.get('parsed', {}).get('key_revoked'):
                dkim_pts = max(dkim_pts - 10, 0)
                issues.append({'severity': 'fail', 'text': f"DKIM selector '{sel['selector']}' key is revoked"})
    else:
        issues.append({'severity': 'fail', 'text': 'No DKIM records found with known selectors'})
    core['dkim'] = {'label': 'DKIM', 'score': dkim_pts, 'max': 25}

    # ── Total + open relay penalty ────────────────────────────────────────
    total = sum(v['score'] for v in core.values())
    if open_relay.get('open_relay_count', 0) > 0:
        total = max(total - 25, 0)
        issues.insert(0, {'severity': 'fail', 'text': 'CRITICAL: Open mail relay detected — your server will be exploited and blacklisted'})

    total = max(min(total, 100), 0)

    if total >= 90:   grade, colour = 'A', 'pass'
    elif total >= 75: grade, colour = 'B', 'pass'
    elif total >= 55: grade, colour = 'C', 'warn'
    elif total >= 35: grade, colour = 'D', 'warn'
    else:             grade, colour = 'F', 'fail'

    return {'score': total, 'grade': grade, 'colour': colour, 'core': core, 'issues': issues}
