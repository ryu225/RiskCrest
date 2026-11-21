"""Regenerate the formatted PDF report from docs/SECURITY_REPORT.md.

Optional build dependencies: pip install mistune weasyprint
"""
from __future__ import annotations

from pathlib import Path

import mistune
from weasyprint import HTML

ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = ROOT / 'docs' / 'SECURITY_REPORT.md'
OUTPUT = ROOT / 'docs' / 'SECURITY_REPORT.pdf'

md = DOCUMENT.read_text(encoding='utf-8')
body_md = md[md.index('## Executive summary'):]
convert = mistune.create_markdown(plugins=['table', 'url'])
body_html = convert(body_md)
body_html = body_html.replace('<h2>7. Evidence and screenshots</h2>', '''
<h2>7. Evidence and screenshots</h2>
<figure class="report-screenshot"><img src="screenshots/04-dashboard.png" alt="The signed-in secure dashboard with profile and personal notes"><figcaption>Figure 1. Secure account dashboard: account summary, encrypted contact field, and sanitized private notes.</figcaption></figure>
''')

styles = '''
@page { size: A4; margin: 19mm 17mm 20mm 17mm;
  @top-left { content: "RISKCREST / SECURITY ENGINEERING"; color: #7b8e97; font-family: DejaVu Sans, Arial, sans-serif; font-size: 7.7pt; letter-spacing: .12em; }
  @top-right { content: "ASSESSMENT REPORT"; color: #7b8e97; font-family: DejaVu Sans, Arial, sans-serif; font-size: 7.7pt; letter-spacing: .12em; }
  @bottom-left { content: "RISKCREST   /   18 NOV 2026"; color: #9dadb1; font-family: DejaVu Sans, Arial, sans-serif; font-size: 7pt; }
  @bottom-right { content: "PAGE " counter(page); color: #496b77; font-family: DejaVu Sans, Arial, sans-serif; font-size: 7.5pt; }
}
@page:first { margin: 0; @top-left { content: none } @top-right { content: none } @bottom-left { content: none } @bottom-right { content: none } }
* { box-sizing: border-box; }
body { margin: 0; font-family: DejaVu Sans, Arial, sans-serif; color:#1e3543; font-size: 9.35pt; line-height: 1.62; }
p { margin: 0 0 3.6mm; }
.cover { height: 297mm; position: relative; padding: 31mm 25mm 20mm; background: #0b2633; color: #f8fffd; page-break-after: always; overflow: hidden; }
.cover:before { content:""; width:150mm; height:150mm; border:1px solid rgba(123,216,195,.13); border-radius: 50%; position:absolute; right:-82mm; top:26mm; }
.cover:after { content:""; width:107mm; height:107mm; border:1px solid rgba(123,216,195,.13); border-radius: 50%; position:absolute; right:-60mm; top:49mm; }
.cover-brand { display: flex; align-items: center; gap:9px; font-size: 11pt; letter-spacing:.1em; font-weight:bold; }
.brand-box { width:29px; height:32px; border:1.5px solid #5ad5bb; border-radius:9px; text-align:center; color:#71e2c9; font-size:20pt; line-height: 28px; }
.brand-suffix { color:#86a9b2; font-weight:normal; }
.cover-eyebrow { font-weight:700; font-size:8.5pt; letter-spacing:.22em; color:#5ce2c3; margin-top:22mm; }
.cover h1 { font-size: 34pt; font-weight:780; line-height:1.12; letter-spacing: -.05em; margin: 7mm 0 6mm; width:150mm; color:white; }
.cover h1 em { color:#78dfc9; font-style:normal; }
.cover-description { color:#aac4c9; font-size:12pt; line-height:1.75; max-width:143mm; }
.cover-photo { position:relative; margin-top:9mm; width:155mm; height:69mm; border: 1px solid #35626c; border-radius:9px; overflow:hidden; }
.cover-photo img { width:100%; height:100%; object-fit:cover; object-position:top center; }
.cover-footer { display:flex; justify-content:space-between; align-items:flex-end; margin-top:10mm; padding-top:5mm; border-top:1px solid #2b4b55; gap:12mm; }
.cover-footer .label { color:#83afb3; font-size:7pt; letter-spacing:.18em; font-weight:750; margin-bottom:2mm; }
.cover-footer .value { color:#f3fff9; font-size:10.5pt; font-weight:700; }
.cover-footer .right { text-align:right; }
.cover-strip { position:absolute; bottom:0; left:0; right:0; height:5mm; background:#42bea9; }
.report { padding-top:0; }
.report h2 { font-size:16.2pt; letter-spacing:-.025em; line-height:1.25; margin:8.7mm 0 3.5mm; padding-bottom:2mm; border-bottom:1.4px solid #d8eae6; color:#143346; break-after:avoid; }
.report h2:first-child { margin-top:0; }
.report h3 { font-size:11.1pt; color:#167b6e; line-height:1.4; margin:6.5mm 0 2.4mm; break-after:avoid; }
.report strong { color:#193f49; }
.report code { font-family: DejaVu Sans Mono, monospace; color:#186e64; background:#f0f7f4; font-size:8.1pt; padding:1px 3px; overflow-wrap:anywhere; white-space:normal; }
.report em { color:#577180; }
.report a { color:#087d74; overflow-wrap:anywhere; text-decoration:none; }
.report ul, .report ol { padding-left:6mm; margin: 2mm 0 4.3mm; }
.report li { margin-bottom:1.4mm; }
.report table { border-collapse: collapse; width:100%; table-layout:fixed; margin:3.5mm 0 6mm; font-size:8.0pt; line-height:1.4; }
.report table thead { display:table-header-group; }
.report table th { background:#113646; color:white; font-weight:720; padding:8px 7px; text-align:left; border:1px solid #113646; }
.report table td { padding:6px 7px; vertical-align:top; border:1px solid #dce8e7; word-break:break-word; overflow-wrap:anywhere; }
.report table tr:nth-child(even) td { background:#f7faf9; }
.report tr { break-inside:avoid; }
.report table:nth-of-type(1) th:first-child { width:31%; }
.report table:nth-of-type(1) th:nth-child(2) { width:34%; }
.report table:nth-of-type(1) th:nth-child(3) { width:35%; }
.report table:nth-of-type(2) th:first-child { width:45%; }
.report table:nth-of-type(2) th:not(:first-child) { text-align:center; }
.report table:nth-of-type(2) td:not(:first-child) { text-align:center; }
.report-screenshot { break-inside:avoid; margin:3mm 0 7mm; padding:3mm; border:1px solid #e3eeeb; background:#fbfdfc; border-radius:4px; }
.report-screenshot img { display:block; width:100%; height:auto; max-height:77mm; object-fit:contain; }
.report-screenshot figcaption { font-size:7.8pt; color:#6f8891; margin-top:3mm; }
.report blockquote { border-left:3px solid #2ebfa5; margin:4mm 0; padding:2mm 4mm; background:#edf8f3; }
.report p { orphans:2; widows:2; }
'''

html = f'''<!doctype html><html><head><meta charset="utf-8"><style>{styles}</style></head><body>
<section class="cover">
  <div class="cover-brand"><span class="brand-box">✓</span><span>SENTINEL<span class="brand-suffix">PORTAL</span></span></div>
  <div class="cover-eyebrow">INFORMATION SECURITY / PROJECT REPORT</div>
  <h1>Securing a web<br>application.<br><em>From vulnerable<br>to protected.</em></h1>
  <div class="cover-description">Building a Secure Web Application - Detection and Mitigation of Security Vulnerabilities</div>
  <div class="cover-photo"><img src="screenshots/01-home.png" alt="RiskCrest home page"></div>
  <div class="cover-footer">
    <div><div class="label">PREPARED BY</div><div class="value">Ryoouf Alsuwidany</div><div style="font-size:9pt;color:#8db8b6;margin-top:2mm">Student ID 443201098</div></div>
    <div class="right"><div class="label">SUBMISSION</div><div class="value">21 November 2026</div><div style="font-size:9pt;color:#8db8b6;margin-top:2mm">15-point assessment</div></div>
  </div>
  <div class="cover-strip"></div>
</section>
<section class="report">{body_html}</section>
</body></html>'''

HTML(string=html, base_url=str(ROOT/'docs')).write_pdf(OUTPUT)
print(f'Generated: {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)')
