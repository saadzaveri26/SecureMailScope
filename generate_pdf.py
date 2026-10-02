import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#56667A"))
        
        # Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 750, "SecureMailScope — Project Architecture & Executive Guide")
            self.setStrokeColor(colors.HexColor("#E2E4E8"))
            self.setLineWidth(0.5)
            self.line(54, 742, 558, 742)
            
        # Footer
        self.setStrokeColor(colors.HexColor("#E2E4E8"))
        self.setLineWidth(0.5)
        self.line(54, 45, 558, 45)
        self.drawString(54, 32, "Confidential & Proprietary — SecureMailScope Forensics")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 32, page_str)
        self.restoreState()

def build_pdf(filename="SecureMailScope_Project_Overview.pdf"):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()
    
    brand_blue = colors.HexColor("#1974B9")
    text_dark = colors.HexColor("#1C1D1F")
    text_muted = colors.HexColor("#56667A")
    bg_light = colors.HexColor("#F6F7F9")
    border_color = colors.HexColor("#E2E4E8")
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=brand_blue,
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=text_muted,
        spaceAfter=15
    )
    
    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=brand_blue,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=11,
        leading=15,
        textColor=text_dark,
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['BodyText'],
        fontName='Helvetica',
        fontSize=9.5,
        leading=13.5,
        textColor=text_dark,
        spaceAfter=6
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=body_style,
        leftIndent=15,
        firstLineIndent=-10,
        spaceAfter=4
    )

    callout_style = ParagraphStyle(
        'CalloutText',
        parent=body_style,
        fontName='Helvetica-Oblique',
        fontSize=9.5,
        leading=14,
        textColor=colors.HexColor("#084C4F")
    )
    
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=text_dark
    )
    
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11.5,
        textColor=colors.white
    )

    story = []

    # Title & Subtitle
    story.append(Paragraph("SecureMailScope", title_style))
    story.append(Paragraph("Cryptographic Posture & Protocol Forensics for Mail Infrastructure", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=brand_blue, spaceBefore=0, spaceAfter=14))

    # Executive Summary
    story.append(Paragraph("1. Executive Summary & Purpose", h1_style))
    story.append(Paragraph(
        "<b>SecureMailScope</b> is an automated forensic engine that audits email protocol cryptography directly "
        "from network packet captures (PCAP/PCAPNG). It evaluates SMTP, IMAP, and POP3 communications without requiring "
        "private server decryption keys, without installing intrusive host agents, and without reading or storing private email message bodies.",
        body_style
    ))
    
    # Callout Box
    callout_data = [[
        Paragraph(
            "<b>The Core Analogy:</b> Inspecting email security with SecureMailScope is like inspecting an armored cash truck. "
            "You do not need to unlock or inspect the money inside the truck to verify that the exterior padlocks are intact, "
            "that the driver did not hand over the keys in cleartext, or that the security protocols were followed.",
            callout_style
        )
    ]]
    callout_table = Table(callout_data, colWidths=[504])
    callout_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#EFF6FC")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#8ED0FE")),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(callout_table)
    story.append(Spacer(1, 10))

    # The Problem
    story.append(Paragraph("2. The Problem: Why Email Cryptography is Fragile", h1_style))
    story.append(Paragraph(
        "Email relies on protocols designed in the early days of the Internet (SMTP, IMAP, POP3). Unlike modern web browsing (HTTPS) "
        "which is encrypted from the very first packet, email security is fraught with historical compromises:",
        body_style
    ))
    
    story.append(Paragraph("• <b>STARTTLS Downgrade Attacks:</b> Mail connections typically start in plain text. A server announces the <code>STARTTLS</code> capability. If an active adversary or malicious middlebox strips this announcement from the cleartext banner, both mail servers fall back to unencrypted transmission without warning.", bullet_style))
    story.append(Paragraph("• <b>Cleartext Authentication Leaks:</b> Misconfigured clients and legacy relay agents frequently transmit credentials (<code>AUTH LOGIN</code>, <code>AUTH PLAIN</code>) before the TLS negotiation has completed, exposing account passwords in the clear.", bullet_style))
    story.append(Paragraph("• <b>Legacy Cipher Support:</b> Servers quietly maintain backward compatibility with cracked ciphers (RC4, 3DES, EXPORT) or deprecated protocol versions (SSLv3, TLS 1.0, TLS 1.1) that can be intercepted or decrypted offline.", bullet_style))
    story.append(Paragraph("• <b>Silent Configuration Drift:</b> Mail server updates or administrative oversights often revert hardened configurations back to insecure defaults over time.", bullet_style))
    story.append(Spacer(1, 8))

    # Real-World Use Cases Table
    story.append(Paragraph("3. Target Personas & Primary Use Cases", h1_style))
    
    use_case_data = [
        [Paragraph("Target Role", table_header), Paragraph("Operational Workflow", table_header), Paragraph("Key Benefit", table_header)],
        [
            Paragraph("<b>SOC & Incident Response</b>", table_cell),
            Paragraph("Investigating suspected mail interception or unauthorized credential leaks from network captures.", table_cell),
            Paragraph("Provides exact packet frame numbers and copyable Wireshark filters proving flaws.", table_cell)
        ],
        [
            Paragraph("<b>Mail Server Administrators</b>", table_cell),
            Paragraph("Hardening Postfix, Dovecot, Exim, or Exchange configurations prior to production deployment.", table_cell),
            Paragraph("Copy-paste remediation snippets to close detected cipher/auth vulnerabilities.", table_cell)
        ],
        [
            Paragraph("<b>Compliance & Security Auditors</b>", table_cell),
            Paragraph("Auditing corporate email cryptographic posture against NIST, ISO 27001, and HIPAA benchmarks.", table_cell),
            Paragraph("Objective 0–100 posture scoring engine with reproducible mathematical deductions.", table_cell)
        ],
        [
            Paragraph("<b>MSSPs & Security Engineers</b>", table_cell),
            Paragraph("Comparing baseline captures against new weekly or monthly traffic to track configuration drift.", table_cell),
            Paragraph("Automated endpoint-by-endpoint diffing flagging degraded or improved security.", table_cell)
        ],
    ]
    
    uc_table = Table(use_case_data, colWidths=[130, 214, 160])
    uc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand_blue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_light])
    ]))
    story.append(uc_table)
    story.append(Spacer(1, 14))

    # Technical Pipeline
    story.append(Paragraph("4. Technical Engine: 6-Stage Forensic Pipeline", h1_style))
    story.append(Paragraph(
        "SecureMailScope processes raw packet captures through a deterministic 6-stage analysis pipeline:",
        body_style
    ))

    pipeline_steps = [
        ("Stage 1: TCP Stream Reassembly", "Raw packets captured out of order or fragmented are reassembled using dpkt into bidirectional TCP application streams across standard mail ports (25, 465, 587, 110, 143, 993, 995)."),
        ("Stage 2: Protocol & Dialog Extraction", "Reconstructs the full mail dialog state machine (SMTP EHLO/HELO, STARTTLS commands, IMAP CAPABILITY, POP3 STLS) and identifies whether the connection uses implicit TLS or explicit STARTTLS."),
        ("Stage 3: Cryptographic Handshake Audit", "Parses TLS records: ClientHello and ServerHello parameters, negotiated TLS version, selected cipher suites, key exchanges, SNI, ALPN, JA3/JA3S client/server fingerprints, and X.509 certificate chains."),
        ("Stage 4: 44 Heuristic Rules & AI Anomaly Detection", "Evaluates 44 deterministic security rules across cipher strength, authentication sequencing, and certificate validity. Concurrently runs an Isolation Forest Machine Learning model to detect statistical behavioral deviations."),
        ("Stage 5: Objective Posture Scoring (0–100)", "Applies credit-score-style mathematical scoring starting at 100 points, deducting weighted penalties based on flaw severity and exposure impact (e.g. -25 for cleartext auth before TLS, -15 for deprecated TLS)."),
        ("Stage 6: Evidence & Remediation Synthesis", "Binds each finding to the exact frame indices, generates copyable Wireshark display filters, and outputs vendor-specific remediation configuration blocks for Postfix, Dovecot, and Exim.")
    ]

    for title, desc in pipeline_steps:
        story.append(Paragraph(f"<b>{title}:</b> {desc}", bullet_style))

    story.append(Spacer(1, 10))

    # Application Modules
    story.append(Paragraph("5. Application Modules & User Interface", h1_style))
    
    modules_data = [
        [Paragraph("Module", table_header), Paragraph("Route", table_header), Paragraph("Forensic Function", table_header)],
        [
            Paragraph("<b>Landing Hub</b>", table_cell),
            Paragraph("<code>/</code>", table_cell),
            Paragraph("Asymmetric product hero with active priority evidence preview and passive analysis boundaries.", table_cell)
        ],
        [
            Paragraph("<b>PCAP Ingestion</b>", table_cell),
            Paragraph("<code>/captures</code>", table_cell),
            Paragraph("Drag-and-drop upload zone (.pcap/.pcapng), SHA-256 verification, status tracking, and file inventory.", table_cell)
        ],
        [
            Paragraph("<b>Executive Overview</b>", table_cell),
            Paragraph("<code>/overview</code>", table_cell),
            Paragraph("Numeral posture score (0–100), letter grade (A–F), factor deduction bars, protocol/transport distributions.", table_cell)
        ],
        [
            Paragraph("<b>Session Inspector</b>", table_cell),
            Paragraph("<code>/sessions</code>", table_cell),
            Paragraph("Dense session table with sliding evidence drawer for TLS parameters, X.509 cert chains, and JA3 fingerprints.", table_cell)
        ],
        [
            Paragraph("<b>Vulnerability Findings</b>", table_cell),
            Paragraph("<code>/findings</code>", table_cell),
            Paragraph("Ranked vulnerability catalog with exact packet frame numbers, Wireshark filters, and remediation commands.", table_cell)
        ],
        [
            Paragraph("<b>Posture Drift</b>", table_cell),
            Paragraph("<code>/drift</code>", table_cell),
            Paragraph("Comparative baseline vs. current capture diffing flagging configuration regressions and upgrades.", table_cell)
        ],
        [
            Paragraph("<b>Compliance Reports</b>", table_cell),
            Paragraph("<code>/reports</code>", table_cell),
            Paragraph("Multi-format exports: raw JSON for SIEM/SOAR ingestion, standalone HTML briefs, and PDF executive summaries.", table_cell)
        ],
    ]

    mod_table = Table(modules_data, colWidths=[110, 84, 310])
    mod_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), brand_blue),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4.5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4.5),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
        ('GRID', (0, 0), (-1, -1), 0.5, border_color),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, bg_light])
    ]))
    story.append(mod_table)
    story.append(Spacer(1, 14))

    # Architecture & Technology
    story.append(Paragraph("6. Architecture & Dual-Mode Runtime", h1_style))
    story.append(Paragraph(
        "SecureMailScope is engineered with a strict decoupled architecture:",
        body_style
    ))
    story.append(Paragraph("• <b>Frontend Layer (Next.js 16 + TypeScript + Tailwind v4):</b> Dense, evidence-first forensic interface strictly compliant with WCAG AA contrast standards. Features custom typography (IBM Plex Sans, IBM Plex Mono, Source Serif 4) and tabular numerals.", bullet_style))
    story.append(Paragraph("• <b>Backend Layer (FastAPI + Python 3.13/3.14):</b> Asynchronous REST API utilizing <code>dpkt</code> for zero-subprocess packet parsing, <code>cryptography</code> for X.509 verification, and <code>scikit-learn</code> for anomaly modeling.", bullet_style))
    story.append(Paragraph("• <b>Fixture Mode (Default):</b> Set <code>NEXT_PUBLIC_USE_FIXTURES=1</code> to explore the complete forensic engine immediately with realistic enterprise capture fixtures without dependencies.", bullet_style))
    story.append(Paragraph("• <b>Live Integration Mode:</b> Set <code>NEXT_PUBLIC_USE_FIXTURES=0</code> to connect directly to the FastAPI server on port 8000 for live capture uploads and real-time packet reassembly.", bullet_style))

    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Successfully generated {filename}")

if __name__ == "__main__":
    out_path = os.path.join(os.path.dirname(__file__), "SecureMailScope_Project_Overview.pdf")
    build_pdf(out_path)
