import asyncio
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
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

    score = _calculate_score(mx, spf, dmarc, dkim, blacklist, mta_sts, open_relay)
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

    score = _calculate_score(mx, spf, dmarc, dkim, blacklist, mta_sts, open_relay)
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


def _calculate_score(mx, spf, dmarc, dkim, blacklist, mta_sts, open_relay) -> dict:
    score = 100
    issues = []

    if not mx.get('records'):
        score -= 20
        issues.append({'severity': 'fail', 'text': 'No MX records found'})

    spf_s = spf.get('status')
    if spf_s == 'missing':
        score -= 20
        issues.append({'severity': 'fail', 'text': 'No SPF record'})
    elif spf_s == 'warning':
        score -= 5
        issues.append({'severity': 'warning', 'text': 'Multiple SPF records (invalid)'})
    elif spf_s == 'ok':
        parsed = spf.get('parsed') or {}
        if parsed.get('all_mechanism') in ('+all', 'all'):
            score -= 15
            issues.append({'severity': 'fail', 'text': 'SPF +all allows any sender'})
        elif parsed.get('all_mechanism') == '~all':
            score -= 5
            issues.append({'severity': 'warning', 'text': 'SPF softfail (~all) — consider -all'})
        if parsed.get('lookup_count', 0) > 10:
            score -= 5
            issues.append({'severity': 'warning', 'text': 'SPF exceeds 10 DNS lookup limit'})

    dmarc_s = dmarc.get('status')
    if dmarc_s == 'missing':
        score -= 15
        issues.append({'severity': 'fail', 'text': 'No DMARC record'})
    elif dmarc_s == 'ok':
        policy = dmarc.get('policy', 'none')
        if policy == 'none':
            score -= 10
            issues.append({'severity': 'warning', 'text': "DMARC policy is 'none' — no enforcement"})
        elif policy == 'quarantine':
            score -= 5
            issues.append({'severity': 'warning', 'text': "DMARC policy is 'quarantine' — consider 'reject'"})

    if dkim.get('status') == 'missing':
        score -= 10
        issues.append({'severity': 'warning', 'text': 'No DKIM records found'})

    listed = blacklist.get('listed_count', 0)
    if listed > 0:
        score -= min(listed * 5, 25)
        issues.append({'severity': 'fail', 'text': f'Listed on {listed} blacklist(s)'})

    if mta_sts.get('status') == 'missing':
        score -= 5
        issues.append({'severity': 'warning', 'text': 'MTA-STS not configured'})

    if open_relay.get('open_relay_count', 0) > 0:
        score -= 20
        issues.append({'severity': 'fail', 'text': 'Open relay detected!'})

    score = max(score, 0)
    if score >= 90:
        grade, colour = 'A', 'pass'
    elif score >= 75:
        grade, colour = 'B', 'pass'
    elif score >= 60:
        grade, colour = 'C', 'warn'
    elif score >= 45:
        grade, colour = 'D', 'warn'
    else:
        grade, colour = 'F', 'fail'

    return {'score': score, 'grade': grade, 'colour': colour, 'issues': issues}
