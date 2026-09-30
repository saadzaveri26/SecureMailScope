from __future__ import annotations
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .common import SEV_COLORS, build_context


def _t(x) -> str:
    s = str(x).replace("\u2192", "->").replace("\u2265", ">=").replace("\u2014", "-")
    return escape(s.encode("latin-1", "replace").decode("latin-1"))


def render(doc: dict) -> bytes:
    c = build_context(doc)
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=8.5, leading=11)
    small = ParagraphStyle("s", parent=body, fontSize=7.5, leading=9.5)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontSize=20, textColor=colors.HexColor("#0f172a"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontSize=13, textColor=colors.HexColor("#1e3a8a"), spaceBefore=12)
    P = lambda t, st=body: Paragraph(_t(t), st)  # noqa: E731
    story = [Paragraph("SecureMailScope", h1), P("Cryptographic Security Posture - Forensic Report", ss["Heading3"]),
             P(f"Analysis {doc['analysis_id']}  |  generated {c['generated_at'][:19]} UTC  |  {c['tool']}", small), Spacer(1, 6)]
    story.append(Paragraph("Executive summary", h2))
    story += [P(x) for x in c["exec"]]
    o, sv = doc["posture"]["overall"], doc["summary"]["findings_by_severity"]
    kp = Table([["Posture", "Critical", "High", "Medium", "Low", "Sessions", "Anomalies"],
                [f"{o['score']}/100 ({o['grade']})", sv["CRITICAL"], sv["HIGH"], sv["MEDIUM"], sv["LOW"], doc["summary"]["sessions"], doc["summary"]["anomalous_sessions"]]], hAlign="LEFT")
    kp.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("FONTSIZE", (0, 0), (-1, -1), 9), ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")), ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    story += [Spacer(1, 6), kp]
    story.append(Paragraph("Chain of custody", h2))
    ct = Table([[P(k, small), P(v, small)] for k, v in c["custody"].items()], colWidths=[35 * mm, 135 * mm])
    ct.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(ct)

    story.append(Paragraph("Endpoint posture", h2))
    rows = [[P(x, small) for x in ("Endpoint", "Proto", "Sess.", "Score", "Transp.", "Proto", "Cipher", "Cert")]]
    prof = {x["endpoint"]: x for x in doc["endpoints"]}
    for ep, v in sorted(doc["posture"]["endpoints"].items(), key=lambda kv: kv[1]["score"]):
        sc = v["subscores"]
        rows.append([P(ep + (f" ({prof[ep]['server_name']})" if prof[ep]["server_name"] else ""), small), P(prof[ep]["protocol"], small), v["sessions"], f"{v['score']} ({v['grade']})",
                     sc["transport"], sc["protocol"], sc["cipher"], sc["certificate"]])
    t = Table(rows, colWidths=[55 * mm, 14 * mm, 12 * mm, 20 * mm, 15 * mm, 15 * mm, 15 * mm, 15 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)

    story.append(Paragraph("Prioritised findings", h2))
    rows = [[P(x, small) for x in ("#", "Pri", "Severity", "Finding / detail", "Endpoint", "Aff.")]]
    sty = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("FONTSIZE", (0, 0), (-1, -1), 8)]
    fl = [f for f in doc["findings"] if f["severity"] != "INFO"]
    for i, f in enumerate(fl, 1):
        rows.append([f["rank"], f["priority"], f["severity"], Paragraph(f"<b>{_t(f['title'])}</b><br/>{_t(f['detail'][:160])}", small), P(f["endpoint"], small), f"{f['affected_sessions']}/{f['total_sessions']}"])
        sty.append(("TEXTCOLOR", (2, i), (2, i), colors.HexColor(SEV_COLORS[f["severity"]])))
        sty.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    t = Table(rows, colWidths=[8 * mm, 9 * mm, 18 * mm, 92 * mm, 30 * mm, 15 * mm], repeatRows=1)
    t.setStyle(TableStyle(sty))
    story.append(t)

    d = doc["drift"]
    if d["baseline_compared"] and d["items"]:
        story.append(Paragraph(f"Cryptographic drift vs baseline (status {d['status']}, score {d['drift_score']}/100)", h2))
        for i in d["items"]:
            rows = [[Paragraph("<b>%s</b> [%s] %s" % (_t(i["title"]), i["severity"], _t(i["endpoint"])), body), ""],
                    [P("Baseline", small), P(i["baseline"], small)], [P("Current", small), P(i["current"], small)],
                    [P("Affected sessions", small), P(i["affected_sessions"], small)]]
            if i.get("observed"):
                rows.append([P("Observations", small), P("; ".join(i["observed"]), small)])
            for ev in i["evidence"][:1]:
                rows.append([P("Evidence", small), P(f"TCP stream {ev['tcp_stream']} / {ev['handshake_message']} / {ev['field']} = {str(ev['value'])[:50]}", small)])
            rows += [[P("Why it matters", small), P(i["why_it_matters"], small)], [P("Recommendation", small), P(i["recommendation"], small)]]
            t = Table(rows, colWidths=[32 * mm, 138 * mm])
            t.setStyle(TableStyle([("SPAN", (0, 0), (1, 0)), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBEFORE", (0, 0), (0, 0), 3, colors.HexColor(SEV_COLORS[i["severity"]]))]))
            story += [KeepTogether([t]), Spacer(1, 4)]

    story.append(Paragraph("Highest-risk sessions (explainable assessment)", h2))
    for k in c["cards"][:8]:
        rows = [[Paragraph(f"<b>{_t(k['title'])}</b> - {k['protocol']} {_t(k['client'])} -&gt; {_t(k['server'])}", body), Paragraph(f"<b>{k['risk_level']}</b> {k['risk_score']}/100", body)]]
        rows += [[P(r["label"], small), P(f"{r['value']}  [{r['status'].upper()}]", small)] for r in k["rows"]]
        rows.append([P("Why", small), P("; ".join(k["why"][:4]), small)])
        rows.append([P("Recommendation", small), P(k["recommendation"], small)])
        t = Table(rows, colWidths=[38 * mm, 132 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story += [KeepTogether([t]), Spacer(1, 4)]

    story.append(Paragraph("Certificates", h2))
    rows = [[P(x, small) for x in ("Subject", "Issuer", "Key", "Hash", "Valid to", "Days")]]
    for fp, ce in doc["certificates"].items():
        rows.append([P(f"{ce['subject_cn']}<br/>{fp[:23]}...", small), P(ce["issuer_cn"] or "", small), f"{ce['public_key']['algorithm']}-{ce['public_key']['size']}", ce["signature"]["hash"], ce["not_after"][:10], ce["days_remaining"]])
    t = Table(rows, colWidths=[55 * mm, 40 * mm, 20 * mm, 15 * mm, 22 * mm, 12 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)

    story.append(Paragraph("Remediation plan", h2))
    rows = [[P(x, small) for x in ("Pri", "Action", "Effort", "Resolves")]] + [[r["priority"], P(r["action"], small), r["effort"], P(", ".join(r["resolves"]), small)] for r in doc["remediation_plan"][:18]]
    t = Table(rows, colWidths=[10 * mm, 100 * mm, 16 * mm, 44 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")), ("FONTSIZE", (0, 0), (-1, -1), 8), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    story.append(t)
    story.append(Paragraph("Methodology & limitations", h2))
    story += [P("- " + x, small) for x in c["limitations"]]

    def footer(canvas, docu):
        canvas.saveState(); canvas.setFont("Helvetica", 7.5); canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(20 * mm, 10 * mm, f"SecureMailScope - {doc['analysis_id']} - sha256 {doc['source']['sha256'][:16]}...")
        canvas.drawRightString(190 * mm, 10 * mm, f"Page {docu.page}"); canvas.restoreState()

    buf = BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=20 * mm, topMargin=16 * mm, bottomMargin=18 * mm, title=f"SecureMailScope {doc['analysis_id']}").build(story, onFirstPage=footer, onLaterPages=footer)
    return buf.getvalue()
