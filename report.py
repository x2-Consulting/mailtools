from fpdf import FPDF
from datetime import datetime


EXPLANATIONS = {
    'mx': {
        'title': 'MX Records (Mail Exchanger)',
        'what': 'MX records tell the internet which mail servers are authorised to receive email on behalf of your domain.',
        'why': 'Without correct MX records, email cannot be delivered to your domain. Properly ordered MX records with priority values ensure reliable failover.',
    },
    'spf': {
        'title': 'SPF (Sender Policy Framework)',
        'what': 'SPF is a DNS record that lists all servers authorised to send email from your domain.',
        'why': 'SPF prevents spammers from forging the "From" address of your domain. A strict -all policy ensures that only authorised servers can send on your behalf, reducing phishing and spam.',
    },
    'dmarc': {
        'title': 'DMARC (Domain-based Message Authentication, Reporting & Conformance)',
        'what': 'DMARC builds on SPF and DKIM to tell receiving mail servers what to do when an email fails authentication — reject, quarantine, or monitor.',
        'why': 'DMARC is the single most impactful email security record. A policy of "reject" prevents attackers from sending fraudulent emails using your domain. DMARC reporting also gives visibility into who is sending email on your behalf.',
    },
    'dkim': {
        'title': 'DKIM (DomainKeys Identified Mail)',
        'what': 'DKIM adds a cryptographic signature to outgoing email, allowing the recipient\'s server to verify the message was not altered in transit.',
        'why': 'DKIM protects email integrity and is required for DMARC alignment. Without DKIM, messages that pass through forwarding or mailing lists may fail SPF, and DMARC will not protect you effectively.',
    },
    'bimi': {
        'title': 'BIMI (Brand Indicators for Message Identification)',
        'what': 'BIMI is a DNS record that points to your brand\'s logo, allowing email clients like Gmail and Apple Mail to display it next to your authenticated emails.',
        'why': 'BIMI requires strong DMARC enforcement (reject or quarantine) and optionally a Verified Mark Certificate (VMC). It increases brand trust and email open rates.',
    },
    'blacklist': {
        'title': 'Blacklist / RBL Checks',
        'what': 'Real-time Blackhole Lists (RBLs) are databases of IP addresses and domains known to send spam or malicious email.',
        'why': 'If your mail server\'s IP is listed on major blacklists (e.g. Spamhaus, Barracuda, TrendMicro ERS), your emails may be blocked or sent to spam for millions of recipients. Regular monitoring is essential.',
    },
    'smtp': {
        'title': 'SMTP Connection Tests',
        'what': 'Tests live connections to your mail servers on ports 25 (SMTP), 587 (Submission), and 465 (SMTPS) to verify they are reachable and properly configured.',
        'why': 'STARTTLS encryption protects email in transit. A server that does not support TLS exposes message content to interception. Verifying connectivity confirms your MX infrastructure is operational.',
    },
}

STATUS_LABEL = {'ok': 'PASS', 'missing': 'MISSING', 'warning': 'WARNING', 'error': 'ERROR', 'fail': 'FAIL'}
STATUS_COLOR = {
    'ok': (34, 197, 94),
    'pass': (34, 197, 94),
    'missing': (239, 68, 68),
    'warning': (245, 158, 11),
    'error': (239, 68, 68),
    'fail': (239, 68, 68),
    'warn': (245, 158, 11),
}


class MailReport(FPDF):
    def __init__(self, domain: str):
        super().__init__()
        self.domain = domain
        self.set_auto_page_break(auto=True, margin=15)

    def header(self):
        self.set_fill_color(15, 17, 23)
        self.rect(0, 0, 210, 22, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 13)
        self.set_xy(10, 6)
        self.cell(0, 10, f'Mail Security Report — {self.domain}', align='L')
        self.set_font('Helvetica', '', 8)
        self.set_xy(0, 6)
        self.cell(200, 10, f'Generated {datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}', align='R')
        self.set_text_color(0, 0, 0)
        self.ln(18)

    def footer(self):
        self.set_y(-12)
        self.set_font('Helvetica', '', 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f'Page {self.page_no()} — MailTool', align='C')

    def score_block(self, score_data: dict):
        score = score_data.get('score', 0)
        grade = score_data.get('grade', 'F')
        colour = score_data.get('colour', 'fail')
        r, g, b = STATUS_COLOR.get(colour, (239, 68, 68))

        self.set_fill_color(r, g, b)
        self.rect(10, self.get_y(), 190, 28, 'F')
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 28)
        self.set_xy(10, self.get_y() + 4)
        self.cell(40, 20, grade, align='C')
        self.set_font('Helvetica', 'B', 16)
        self.set_xy(50, self.get_y() - 20 + 4)
        self.cell(60, 20, f'Score: {score}/100', align='L')

        issues = score_data.get('issues', [])
        if issues:
            self.set_font('Helvetica', '', 8)
            self.set_xy(130, self.get_y() - 20 + 4)
            issue_text = '  |  '.join(i['text'] for i in issues[:4])
            self.multi_cell(70, 5, issue_text)

        self.set_text_color(0, 0, 0)
        self.ln(16)

    def section(self, key: str, status: str, record: str = '', details: list = None):
        exp = EXPLANATIONS.get(key, {})
        title = exp.get('title', key.upper())
        what = exp.get('what', '')
        why = exp.get('why', '')

        # Section title bar
        self.set_fill_color(26, 29, 39)
        self.set_text_color(255, 255, 255)
        self.set_font('Helvetica', 'B', 10)
        label = STATUS_LABEL.get(status, status.upper())
        r, g, b = STATUS_COLOR.get(status, (100, 100, 100))
        self.set_fill_color(26, 29, 39)
        self.rect(10, self.get_y(), 190, 8, 'F')
        self.set_xy(12, self.get_y() + 1)
        self.cell(140, 6, title, align='L')
        # Status badge
        self.set_fill_color(r, g, b)
        self.rect(170, self.get_y() - 5, 30, 6, 'F')
        self.set_xy(170, self.get_y() - 5)
        self.cell(30, 6, label, align='C')
        self.set_text_color(0, 0, 0)
        self.ln(10)

        # Explanation
        self.set_font('Helvetica', 'B', 8)
        self.set_x(12)
        self.cell(0, 5, 'What it is:', ln=True)
        self.set_font('Helvetica', '', 8)
        self.set_x(12)
        self.set_text_color(60, 60, 60)
        self.multi_cell(186, 4, what)
        self.set_text_color(0, 0, 0)
        self.ln(1)

        self.set_font('Helvetica', 'B', 8)
        self.set_x(12)
        self.cell(0, 5, 'Why it matters:', ln=True)
        self.set_font('Helvetica', '', 8)
        self.set_x(12)
        self.set_text_color(60, 60, 60)
        self.multi_cell(186, 4, why)
        self.set_text_color(0, 0, 0)
        self.ln(2)

        # Record
        if record:
            self.set_font('Courier', '', 7)
            self.set_fill_color(240, 240, 240)
            self.set_x(12)
            self.multi_cell(186, 4, record, fill=True)
            self.ln(2)

        # Details / findings
        if details:
            for item in details:
                sev = item.get('severity', 'info')
                text = item.get('text', str(item))
                cr, cg, cb = STATUS_COLOR.get(sev, (100, 100, 100))
                self.set_fill_color(cr, cg, cb)
                self.rect(12, self.get_y(), 3, 4, 'F')
                self.set_x(17)
                self.set_font('Helvetica', '', 8)
                self.set_text_color(40, 40, 40)
                self.cell(0, 4, text, ln=True)
                self.set_text_color(0, 0, 0)

        self.ln(4)


def build_pdf(data: dict) -> bytes:
    domain = data['domain']
    pdf = MailReport(domain)
    pdf.add_page()

    # Score block
    pdf.score_block(data.get('score', {}))
    pdf.ln(4)

    # MX
    mx = data.get('mx', {})
    mx_lines = [f"  {r['priority']}  {r['host']}  ({r.get('ip', 'N/A')})"
                for r in mx.get('records', [])]
    pdf.section('mx', mx.get('status', 'error'),
                record='\n'.join(mx_lines) if mx_lines else 'No MX records found')

    # SPF
    spf = data.get('spf', {})
    spf_details = []
    if spf.get('parsed'):
        for w in spf['parsed'].get('warnings', []):
            spf_details.append({'severity': 'warning', 'text': w})
    pdf.section('spf', spf.get('status', 'error'),
                record=spf.get('record', ''),
                details=spf_details or None)

    # DMARC
    dmarc = data.get('dmarc', {})
    dmarc_details = []
    if dmarc.get('parsed'):
        for w in dmarc['parsed'].get('warnings', []):
            dmarc_details.append({'severity': 'warning', 'text': w})
    pdf.section('dmarc', dmarc.get('status', 'error'),
                record=dmarc.get('record', ''),
                details=dmarc_details or None)

    # DKIM
    dkim = data.get('dkim', {})
    dkim_details = []
    for sel in dkim.get('found_selectors', []):
        dkim_details.append({'severity': 'ok', 'text': f"Selector '{sel['selector']}' found at {sel['fqdn']}"})
        for w in sel.get('parsed', {}).get('warnings', []):
            dkim_details.append({'severity': 'warning', 'text': f"  {sel['selector']}: {w}"})
    if not dkim_details:
        dkim_details.append({'severity': 'fail', 'text': f"No DKIM records found ({dkim.get('selectors_checked', 0)} selectors checked)"})
    pdf.section('dkim', dkim.get('status', 'error'), details=dkim_details)

    # BIMI
    bimi = data.get('bimi', {})
    bimi_details = []
    if bimi.get('parsed'):
        for w in bimi['parsed'].get('warnings', []):
            bimi_details.append({'severity': 'warning', 'text': w})
    pdf.section('bimi', bimi.get('status', 'missing'),
                record=bimi.get('record', ''),
                details=bimi_details or None)

    # Blacklist
    bl = data.get('blacklist', {})
    bl_details = []
    for entry in bl.get('listed', []):
        bl_details.append({'severity': 'fail', 'text': f"{entry['ip']} listed on {entry['name']}: {entry.get('reason', '')}"})
    if not bl_details:
        bl_details.append({'severity': 'ok', 'text': f"Clean across {bl.get('lists_checked', 0)} lists"})
    pdf.section('blacklist', 'fail' if bl.get('listed_count', 0) > 0 else 'ok',
                details=bl_details)

    # SMTP
    smtp = data.get('smtp', {})
    smtp_details = []
    for r in smtp.get('results', []):
        if r.get('connected'):
            tls_str = f"TLS {r.get('tls_version', '')} {r.get('cipher', '')}".strip()
            smtp_details.append({
                'severity': 'ok' if r.get('tls_established') else 'warning',
                'text': f"{r['host']}:{r['port']} connected ({r.get('latency_ms')}ms) — {tls_str or 'No TLS'}"
            })
        else:
            smtp_details.append({
                'severity': 'fail',
                'text': f"{r['host']}:{r['port']} — {r.get('error', 'Failed')}"
            })
    pdf.section('smtp', smtp.get('status', 'error'), details=smtp_details or None)

    return bytes(pdf.output())
