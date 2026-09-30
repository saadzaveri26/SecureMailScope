from __future__ import annotations
from html import escape as e

from .common import SEV_COLORS, build_context

CSS = """
:root{--bg:#f8fafc;--fg:#0f172a;--mut:#64748b;--card:#fff;--bd:#e2e8f0}
@media(prefers-color-scheme:dark){:root{--bg:#0b1220;--fg:#e2e8f0;--mut:#94a3b8;--card:#111a2e;--bd:#22304a}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:auto;padding:28px 20px}h1{margin:0 0 4px;font-size:26px}h2{margin:34px 0 10px;font-size:18px;border-bottom:2px solid var(--bd);padding-bottom:6px}
.mut{color:var(--mut)}.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px;margin:10px 0}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}.kpi b{display:block;font-size:26px}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--bd);vertical-align:top}th{color:var(--mut);font-weight:600}
.badge{display:inline-block;padding:1px 8px;border-radius:99px;color:#fff;font-size:11px;font-weight:700}
.bar{height:8px;background:var(--bd);border-radius:4px;overflow:hidden}.bar i{display:block;height:100%;background:#2563eb}
.ok{color:#16a34a}.warn{color:#ca8a04}.fail{color:#dc2626}.info{color:var(--mut)}code,pre{background:var(--bd);border-radius:4px;padding:1px 5px;font-size:12px}
pre{padding:8px;overflow:auto;white-space:pre-wrap}@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def badge(sev):
    return f'<span class="badge" style="background:{SEV_COLORS.get(sev, "#64748b")}">{e(sev)}</span>'


def _bars(d: dict, total=None):
    total = total or sum(d.values()) or 1
    return "".join(f'<tr><td>{e(str(k))}</td><td style="width:45%"><div class="bar"><i style="width:{v / total * 100:.1f}%"></i></div></td><td>{v} ({v / total * 100:.0f}%)</td></tr>'
                   for k, v in sorted(d.items(), key=lambda kv: -kv[1]))


def render(doc: dict) -> str:
    c = build_context(doc)
    s, p = doc["summary"], doc["posture"]
    o = p["overall"]
    sev = s["findings_by_severity"]
    h = [f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>SecureMailScope Report {e(doc['analysis_id'])}</title><style>{CSS}</style></head><body><main>",
         f"<h1>SecureMailScope - Cryptographic Posture Report</h1><div class='mut'>Analysis {e(doc['analysis_id'])} &middot; generated {e(c['generated_at'][:19])} UTC &middot; {e(c['tool'])}</div>"]
    h.append("<h2>Executive summary</h2><div class='card'>" + "".join(f"<p>{e(x)}</p>" for x in c["exec"]) + "</div>")
    h.append("<div class='grid'>" + f"<div class='card kpi'><span class='mut'>Posture score</span><b>{o['score']}/100</b>Grade {o['grade']}</div>"
             + "".join(f"<div class='card kpi'><span class='mut'>{k.title()}</span><b style='color:{SEV_COLORS[k]}'>{sev[k]}</b>findings</div>" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
             + f"<div class='card kpi'><span class='mut'>Sessions</span><b>{s['sessions']}</b>{s['endpoints']} endpoints</div>"
             + f"<div class='card kpi'><span class='mut'>ML anomalies</span><b>{s['anomalous_sessions']}</b>sessions</div></div>")
    h.append("<h2>Chain of custody</h2><div class='card'><table>" + "".join(f"<tr><th>{k}</th><td><code>{e(str(v))}</code></td></tr>" for k, v in c["custody"].items()) + "</table></div>")
    h.append("<h2>Endpoint posture</h2><div class='card'><table><tr><th>Endpoint</th><th>Protocol</th><th>Sessions</th><th>Score</th><th>Transport</th><th>Protocol</th><th>Cipher</th><th>Certificate</th><th>PFS</th></tr>")
    prof = {x["endpoint"]: x for x in doc["endpoints"]}
    for ep, v in sorted(p["endpoints"].items(), key=lambda kv: kv[1]["score"]):
        ss = v["subscores"]
        h.append(f"<tr><td>{e(ep)}<div class='mut'>{e(prof[ep]['server_name'] or '')}</div></td><td>{e(prof[ep]['protocol'])}</td><td>{v['sessions']}</td><td><b>{v['score']}</b> ({v['grade']})</td>"
                 f"<td>{ss['transport']}</td><td>{ss['protocol']}</td><td>{ss['cipher']}</td><td>{ss['certificate']}</td><td>{'-' if v['forward_secrecy_ratio'] is None else f'{v['forward_secrecy_ratio'] * 100:.0f}%'}</td></tr>")
    h.append("</table></div>")
    h.append("<h2>Prioritised findings</h2><div class='card'><table><tr><th>#</th><th>Pri</th><th>Severity</th><th>Finding</th><th>Endpoint</th><th>Affected</th><th>Remediation</th></tr>")
    for f in doc["findings"]:
        if f["severity"] == "INFO":
            continue
        rem = "<br>".join(e(x) for x in f["remediation"][:2])
        h.append(f"<tr><td>{f['rank']}</td><td>{f['priority']}</td><td>{badge(f['severity'])}</td><td><b>{e(f['title'])}</b><div class='mut'>{e(f['detail'])}</div></td>"
                 f"<td>{e(f['endpoint'])}</td><td>{f['affected_sessions']}/{f['total_sessions']}</td><td>{rem}</td></tr>")
    h.append("</table></div>")
    d = doc["drift"]
    if d["baseline_compared"]:
        h.append(f"<h2>Cryptographic drift vs baseline</h2><div class='card'>Status: <b>{e(d['status'])}</b> &middot; drift score {d['drift_score']}/100</div>")
        for i in d["items"]:
            h.append(f"<div class='card'><div>{badge(i['severity'])} <b>{e(i['title'])}</b> <span class='mut'>{e(i['endpoint'])} &middot; {i['drift_id']}</span></div><table>"
                     f"<tr><th>Baseline</th><td>{e(str(i['baseline']))}</td></tr><tr><th>Current</th><td>{e(str(i['current']))}</td></tr>"
                     f"<tr><th>Affected sessions</th><td>{i['affected_sessions']}</td></tr>"
                     + (f"<tr><th>Observations</th><td>{'<br>'.join(e(x) for x in i['observed'])}</td></tr>" if i.get("observed") else "")
                     + "".join(f"<tr><th>Evidence</th><td>TCP stream {ev['tcp_stream']} &middot; {e(ev['handshake_message'])} &middot; {e(ev['field'])} = {e(str(ev['value']))[:60]}</td></tr>" for ev in i["evidence"][:2])
                     + f"<tr><th>Why it matters</th><td>{e(i['why_it_matters'])}</td></tr><tr><th>Recommendation</th><td>{e(i['recommendation'])}</td></tr></table></div>")
    h.append("<h2>Highest-risk sessions (explainable assessment)</h2>")
    for k in c["cards"]:
        rows = "".join(f"<tr><td>{e(r['label'])}</td><td>{e(r['value'])}</td><td class='{r['status']}'>{ {'ok': 'OK', 'warn': 'WARN', 'fail': 'FAIL', 'info': 'INFO'}[r['status']] }</td></tr>" for r in k["rows"])
        h.append(f"<div class='card'><b>{e(k['title'])}</b> &middot; {e(k['protocol'])} &middot; {e(k['client'])} -&gt; {e(k['server'])} {badge(k['risk_level'])} <span class='mut'>risk {k['risk_score']}/100</span>"
                 f"<table>{rows}</table><b>Why?</b><ul>{''.join(f'<li>{e(w)}</li>' for w in k['why'])}</ul><b>Recommendation:</b> {e(k['recommendation'])}</div>")
    h.append("<h2>Cryptographic inventory</h2><div class='grid'>")
    for title, dd in (("TLS versions", s["tls_versions"]), ("Key exchange", s["key_exchange"]), ("Cipher suites", s["cipher_suites"]), ("Transport", s["sessions_by_transport"])):
        h.append(f"<div class='card'><b>{title}</b><table>{_bars(dd)}</table></div>")
    h.append("</div><h2>Certificates</h2><div class='card'><table><tr><th>Subject</th><th>Issuer</th><th>Key</th><th>Signature</th><th>Valid</th><th>Days left</th></tr>")
    for fp, ce in doc["certificates"].items():
        h.append(f"<tr><td>{e(ce['subject_cn'] or ce['subject'])}<div class='mut'><code>{fp[:23]}...</code></div></td><td>{e(ce['issuer_cn'] or '')}</td><td>{ce['public_key']['algorithm']}-{ce['public_key']['size']}</td>"
                 f"<td>{e(ce['signature']['hash'])}</td><td>{ce['not_before'][:10]} to {ce['not_after'][:10]}</td><td class='{'fail' if ce['expired'] else ''}'>{ce['days_remaining']}</td></tr>")
    ml = s["message_layer"]
    h.append(f"</table></div><h2>Message-layer security (PGP / S-MIME)</h2><div class='card'>PGP sessions: <b>{ml['pgp_sessions']}</b> &middot; S/MIME sessions: <b>{ml['smime_sessions']}</b> &middot; protected messages over plaintext transport: <b>{ml['plaintext_with_message_protection']}</b></div>")
    h.append("<h2>Remediation plan</h2><div class='card'><table><tr><th>Priority</th><th>Action</th><th>Effort</th><th>Resolves</th></tr>")
    for r in doc["remediation_plan"][:20]:
        h.append(f"<tr><td>{r['priority']}</td><td>{e(r['action'])}</td><td>{r['effort']}</td><td>{e(', '.join(r['resolves']))}</td></tr>")
    h.append("</table></div><h2>Methodology &amp; limitations</h2><div class='card'><ul>" + "".join(f"<li>{e(x)}</li>" for x in c["limitations"]) + "</ul></div></main></body></html>")
    return "".join(h)
