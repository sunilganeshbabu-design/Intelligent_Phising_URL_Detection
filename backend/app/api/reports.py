import io
import csv
import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from sqlalchemy.orm import Session

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, 
    HRFlowable, KeepTogether, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas

from ..core.database import get_db
from ..core.config import settings
from ..core.security import get_current_user_optional
from ..models.db_models import User, URLScan, URLFeatures, Report
from ..modules.feature_extraction import URLFeatureExtractor

router = APIRouter(prefix="/reports", tags=["Reports"])


class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas to dynamically compute and render exact total page count ('Page X of Y')
    along with professional corporate running headers and footers.
    """
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

    def draw_page_decorations(self, page_count: int):
        self.saveState()
        
        # Bottom Footer Divider & Metadata
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.75)
        self.line(36, 30, 612 - 36, 30)
        
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#0284C7"))
        self.drawString(36, 18, "PHISHGUARD AI")
        
        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(108, 18, "•   Intelligent Phishing Detection & Explainable AI Audit Report")
        
        page_text = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(612 - 36, 18, page_text)
        
        # Running Top Header on Subsequent Pages
        if self._pageNumber > 1:
            self.setStrokeColor(colors.HexColor("#E2E8F0"))
            self.setLineWidth(0.5)
            self.line(36, 792 - 28, 612 - 36, 792 - 28)
            
            self.setFont("Helvetica-Bold", 7.5)
            self.setFillColor(colors.HexColor("#0284C7"))
            self.drawString(36, 792 - 22, "PHISHGUARD AI")
            self.setFont("Helvetica", 7.5)
            self.setFillColor(colors.HexColor("#64748B"))
            self.drawString(108, 792 - 22, "•   Phishing URL Security Audit Report (Confidential)")
            
            self.drawRightString(612 - 36, 792 - 22, "Explainable AI (XAI) Engine")
            
        self.restoreState()


def generate_pdf_report(scan: URLScan, features: Optional[URLFeatures] = None) -> str:
    """
    Generates a concise, high-impact, professional Cybersecurity Audit PDF Report (2 pages)
    containing ONLY the 7 required core sections with zero unnecessary internal dumps.
    """
    settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"scan_report_{scan.id}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    file_path = settings.REPORTS_DIR / filename
    
    # Printable area: 612 x 792 (Letter). Margins: 36pt (0.5 inch). Printable width: 540pt.
    doc = SimpleDocTemplate(
        str(file_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=32,
        bottomMargin=38
    )
    
    styles = getSampleStyleSheet()
    
    # Custom Typography Styles
    title_style = ParagraphStyle(
        'DocMainTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=19,
        textColor=colors.HexColor('#0F172A'),
        spaceAfter=1
    )
    
    subtitle_style = ParagraphStyle(
        'DocMainSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#64748B'),
        spaceAfter=4
    )
    
    section_h2 = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=9.5,
        leading=12,
        textColor=colors.HexColor('#0F172A'),
        spaceBefore=7,
        spaceAfter=4,
        keepWithNext=True
    )
    
    body_text = ParagraphStyle(
        'AuditBody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=colors.HexColor('#334155')
    )
    
    mono_url_style = ParagraphStyle(
        'MonoUrl',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0369A1'),
        wordWrap='CJK'
    )
    
    table_header_style = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=9.5,
        textColor=colors.white
    )
    
    table_cell_style = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#1E293B')
    )
    
    table_cell_bold = ParagraphStyle(
        'TableCellBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor('#0F172A')
    )

    # Extract or fallback features
    raw = {}
    if features and features.raw_features:
        raw = features.raw_features
    elif features:
        raw = {
            "url_length": features.url_length,
            "domain_length": features.domain_length,
            "subdomain_count": features.subdomain_count,
            "count_dots": features.count_dots,
            "count_hyphens": features.count_hyphens,
            "https_status": features.https_status,
            "ip_address": features.ip_address,
            "has_at_symbol": features.has_at_symbol,
            "has_double_slash_redirect": features.has_double_slash_redirect,
            "has_prefix_suffix": features.has_prefix_suffix,
            "is_shortened_url": features.is_shortened_url,
            "suspicious_keywords": features.suspicious_keywords,
            "entropy": features.entropy,
            "tld_risk_score": features.tld_risk_score,
        }
    else:
        f_dict, _, f_words, f_tld = URLFeatureExtractor.extract(scan.url)
        raw = f_dict
        raw["detected_suspicious_words"] = f_words
        raw["detected_tld"] = f_tld

    # Key metric calculations
    is_phishing = scan.prediction.lower() == "phishing" or scan.phishing_probability >= 50.0
    phish_prob = float(scan.phishing_probability or 0.0)
    legit_prob = round(max(0.0, 100.0 - phish_prob), 1)
    conf_score = float(scan.confidence_score or 0.0)
    
    # Normalize risk tier
    raw_risk = (scan.risk_level or "Low").strip()
    if raw_risk.lower() in ["safe", "low"]:
        risk_tier = "Low"
    elif raw_risk.lower() in ["medium", "moderate"]:
        risk_tier = "Medium"
    elif raw_risk.lower() in ["high"]:
        risk_tier = "High"
    elif raw_risk.lower() in ["critical"]:
        risk_tier = "Critical"
    else:
        risk_tier = "Low" if not is_phishing else "High"
        
    prediction_label = "Phishing" if is_phishing else "Legitimate"
    
    https_status = bool(raw.get("https_status", False))
    ip_address = bool(raw.get("ip_address", False))
    url_len = int(raw.get("url_length", len(scan.url)))
    domain_len = int(raw.get("domain_length", len(scan.domain or "")))
    subdomain_count = int(raw.get("subdomain_count", 0))
    suspicious_kw_count = int(raw.get("suspicious_keywords", 0))
    detected_words = raw.get("detected_suspicious_words") or []
    if isinstance(detected_words, str):
        detected_words = [w.strip() for w in detected_words.split(",") if w.strip()]
        
    has_prefix_suffix = bool(raw.get("has_prefix_suffix", False))
    has_at_symbol = bool(raw.get("has_at_symbol", False))
    has_double_slash = bool(raw.get("has_double_slash_redirect", False))
    is_shortened = bool(raw.get("is_shortened_url", False))
    entropy_val = float(raw.get("entropy", 3.5))
    tld_risk = float(raw.get("tld_risk_score", 0.1))
    
    elements = []
    
    # -------------------------------------------------------------
    # DOCUMENT HEADER
    # -------------------------------------------------------------
    badge_color = '#DC2626' if is_phishing else '#16A34A'
    header_table_data = [
        [
            Paragraph("<b>PHISHING URL SECURITY AUDIT REPORT</b>", title_style),
            Paragraph(f"<b>SECURITY AUDIT</b><br/><font color='{badge_color}'>REF: PG-AUDIT-{scan.id:05d}</font>", ParagraphStyle('RightRef', parent=styles['Normal'], alignment=2, fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.HexColor(badge_color)))
        ]
    ]
    header_table = Table(header_table_data, colWidths=[380, 160])
    header_table.setStyle(TableStyle([
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('PADDING', (0, 0), (-1, -1), 0),
    ]))
    elements.append(header_table)
    
    elements.append(Paragraph(
        "Executive Cybersecurity Risk Assessment & Explainable AI (XAI) Diagnostic Audit",
        subtitle_style
    ))
    elements.append(HRFlowable(width="100%", thickness=1.25, color=colors.HexColor('#0284C7'), spaceBefore=2, spaceAfter=6))
    
    # -------------------------------------------------------------
    # SECTION 1: REPORT INFORMATION
    # -------------------------------------------------------------
    elements.append(Paragraph("1. REPORT INFORMATION", section_h2))
    
    scan_dt = scan.created_at or datetime.datetime.utcnow()
    formatted_date = scan_dt.strftime('%B %d, %Y at %H:%M:%S UTC')
    
    info_data = [
        [
            Paragraph("<b>Report Title:</b>", table_cell_bold),
            Paragraph("Phishing URL Security Audit Report", table_cell_style),
            Paragraph("<b>Scan ID:</b>", table_cell_bold),
            Paragraph(f"#{scan.id} (PG-SCAN-{scan.id:05d})", table_cell_style)
        ],
        [
            Paragraph("<b>Date and Time:</b>", table_cell_bold),
            Paragraph(formatted_date, table_cell_style),
            Paragraph("<b>Domain:</b>", table_cell_bold),
            Paragraph(f"<code>{scan.domain or 'N/A'}</code>", table_cell_style)
        ],
        [
            Paragraph("<b>Analyzed URL:</b>", table_cell_bold),
            Paragraph(f"{scan.url}", mono_url_style),
            Paragraph("<b>Model Engine:</b>", table_cell_bold),
            Paragraph(f"{scan.model_name or 'XGBoost model'} (XAI Calibrated)", table_cell_style)
        ]
    ]
    
    info_table = Table(info_data, colWidths=[95, 175, 95, 175])
    info_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 3.5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    elements.append(info_table)
    elements.append(Spacer(1, 4))
    
    # -------------------------------------------------------------
    # SECTION 2: FINAL VERDICT
    # -------------------------------------------------------------
    elements.append(Paragraph("2. FINAL VERDICT", section_h2))
    
    if is_phishing:
        if risk_tier == "Critical":
            v_card_bg = colors.HexColor('#FEF2F2')
            v_card_border = colors.HexColor('#B91C1C')
            v_text_color = colors.HexColor('#991B1B')
            v_badge_bg = colors.HexColor('#B91C1C')
            v_title = "🚨 CRITICAL PHISHING THREAT DETECTED"
            v_desc = "This URL exhibits verified malicious deception patterns characteristic of active credential harvesting or brand impersonation."
        else:
            v_card_bg = colors.HexColor('#FEF2F2')
            v_card_border = colors.HexColor('#DC2626')
            v_text_color = colors.HexColor('#991B1B')
            v_badge_bg = colors.HexColor('#DC2626')
            v_title = "🚨 PHISHING THREAT DETECTED"
            v_desc = "This URL exhibits malicious indicators characteristic of phishing campaigns, brand spoofing, or fraudulent deception."
    elif risk_tier == "Medium":
        v_card_bg = colors.HexColor('#FFFBEB')
        v_card_border = colors.HexColor('#D97706')
        v_text_color = colors.HexColor('#92400E')
        v_badge_bg = colors.HexColor('#D97706')
        v_title = "⚠️ SUSPICIOUS / MEDIUM RISK URL"
        v_desc = "Non-standard URL characteristics detected. Exercise caution and verify authority before entering any sensitive details."
    else:
        v_card_bg = colors.HexColor('#F0FDF4')
        v_card_border = colors.HexColor('#16A34A')
        v_text_color = colors.HexColor('#166534')
        v_badge_bg = colors.HexColor('#16A34A')
        v_title = "🛡️ VERIFIED LEGITIMATE / SAFE"
        v_desc = "Structural parameters and security heuristics align with legitimate internet standards. No malicious deception indicators found."
        
    verdict_table_data = [
        [
            Paragraph(f"<font color='white'><b>{v_title}</b></font>", ParagraphStyle('VTitle', fontName='Helvetica-Bold', fontSize=10, leading=12, textColor=colors.white)),
            Paragraph(f"<font color='white'><b>RISK LEVEL: {risk_tier.upper()}</b></font>", ParagraphStyle('VBadge', fontName='Helvetica-Bold', fontSize=8.5, leading=12, alignment=2, textColor=colors.white))
        ],
        [
            Paragraph(f"<font color='{v_text_color.hexval()}'>{v_desc}</font>", ParagraphStyle('VDesc', fontName='Helvetica', fontSize=7.5, leading=10, textColor=v_text_color)),
            Paragraph("")
        ]
    ]
    
    # 5-Column Core Metrics Strip
    metrics_row_data = [
        [
            Paragraph(f"<font size='6.5' color='#64748B'>PREDICTION</font><br/><b><font size='9' color='{v_text_color.hexval()}'>{prediction_label.upper()}</font></b>", table_cell_style),
            Paragraph(f"<font size='6.5' color='#64748B'>RISK LEVEL</font><br/><b><font size='9' color='{v_text_color.hexval()}'>{risk_tier.upper()}</font></b>", table_cell_style),
            Paragraph(f"<font size='6.5' color='#64748B'>CONFIDENCE SCORE</font><br/><b><font size='9' color='#0F172A'>{conf_score:.1f}%</font></b>", table_cell_style),
            Paragraph(f"<font size='6.5' color='#64748B'>PHISHING PROB.</font><br/><b><font size='9' color='#DC2626'>{phish_prob:.1f}%</font></b>", table_cell_style),
            Paragraph(f"<font size='6.5' color='#64748B'>LEGITIMATE PROB.</font><br/><b><font size='9' color='#16A34A'>{legit_prob:.1f}%</font></b>", table_cell_style)
        ]
    ]
    
    verdict_table = Table(verdict_table_data, colWidths=[380, 160])
    verdict_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), v_badge_bg),
        ('BACKGROUND', (0, 1), (-1, 1), v_card_bg),
        ('SPAN', (0, 1), (1, 1)),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('BOX', (0, 0), (-1, -1), 1, v_card_border),
    ]))
    
    metrics_table = Table(metrics_row_data, colWidths=[108, 108, 108, 108, 108])
    metrics_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.white),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#CBD5E1')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    
    elements.append(verdict_table)
    elements.append(Spacer(1, 2))
    elements.append(metrics_table)
    elements.append(Spacer(1, 4))
    
    # -------------------------------------------------------------
    # SECTION 3: URL SECURITY ANALYSIS
    # -------------------------------------------------------------
    elements.append(Paragraph("3. URL SECURITY ANALYSIS", section_h2))
    
    # Structural classification
    if has_prefix_suffix:
        structure_desc = "Yes (Hyphenated Brand Spoofing)"
    elif has_at_symbol:
        structure_desc = "Yes (RFC-1738 @ Delimiter Redirection)"
    elif has_double_slash:
        structure_desc = "Yes (Double Slash // Redirection Trick)"
    elif is_shortened:
        structure_desc = "Yes (URL Shortener Obfuscation)"
    elif "xn--" in (scan.domain or "").lower():
        structure_desc = "Yes (IDN Homograph Punycode)"
    else:
        structure_desc = "No (Canonical Structure)"
        
    kw_desc = "None detected"
    if suspicious_kw_count > 0:
        if detected_words:
            kw_desc = f"Yes ({suspicious_kw_count} keyword{'s' if suspicious_kw_count > 1 else ''}: {', '.join(detected_words[:3])})"
        else:
            kw_desc = f"Yes ({suspicious_kw_count} keyword{'s' if suspicious_kw_count > 1 else ''})"
            
    tld_desc = f"{tld_risk*100:.0f}% Risk ({'High-Risk Abuse TLD' if tld_risk >= 0.6 else 'Standard TLD'})"
    entropy_desc = f"{entropy_val:.2f} bits ({'High Randomness' if entropy_val >= 4.2 else 'Normal Pattern'})"
    
    analysis_data = [
        [
            Paragraph("Security Characteristic", table_header_style),
            Paragraph("Diagnostic Status", table_header_style),
            Paragraph("Security Characteristic", table_header_style),
            Paragraph("Diagnostic Status", table_header_style)
        ],
        [
            Paragraph("<b>HTTPS</b>", table_cell_bold),
            Paragraph("<font color='#16A34A'><b>Yes (Valid TLS / SSL)</b></font>" if https_status else "<font color='#DC2626'><b>No (Insecure HTTP)</b></font>", table_cell_style),
            Paragraph("<b>Domain</b>", table_cell_bold),
            Paragraph(f"<code>{scan.domain}</code>", table_cell_style)
        ],
        [
            Paragraph("<b>URL Length</b>", table_cell_bold),
            Paragraph(f"{url_len} characters ({'Elevated' if url_len > 75 else 'Normal'})", table_cell_style),
            Paragraph("<b>Domain Length</b>", table_cell_bold),
            Paragraph(f"{domain_len} characters", table_cell_style)
        ],
        [
            Paragraph("<b>Number of Subdomains</b>", table_cell_bold),
            Paragraph(f"{subdomain_count} level(s)" + (" <font color='#DC2626'><b>(⚠️ Deeply Nested)</b></font>" if subdomain_count > 2 else ""), table_cell_style),
            Paragraph("<b>Suspicious Keywords</b>", table_cell_bold),
            Paragraph(f"<font color='#DC2626'><b>{kw_desc}</b></font>" if suspicious_kw_count > 0 else kw_desc, table_cell_style)
        ],
        [
            Paragraph("<b>IP Address Usage</b>", table_cell_bold),
            Paragraph("<font color='#DC2626'><b>Yes (Direct IP Host)</b></font>" if ip_address else "No (DNS Host)", table_cell_style),
            Paragraph("<b>Suspicious URL Structure</b>", table_cell_bold),
            Paragraph(f"<font color='#DC2626'><b>{structure_desc}</b></font>" if "Yes" in structure_desc else structure_desc, table_cell_style)
        ],
        [
            Paragraph("<b>TLD Abuse Rating</b>", table_cell_bold),
            Paragraph(f"<font color='#DC2626'><b>{tld_desc}</b></font>" if tld_risk >= 0.6 else tld_desc, table_cell_style),
            Paragraph("<b>Shannon Entropy</b>", table_cell_bold),
            Paragraph(f"<font color='#DC2626'><b>{entropy_desc}</b></font>" if entropy_val >= 4.2 else entropy_desc, table_cell_style)
        ]
    ]
    
    analysis_table = Table(analysis_data, colWidths=[120, 150, 120, 150])
    analysis_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E293B')),
        ('PADDING', (0, 0), (-1, -1), 3),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F8FAFC'), colors.white]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    elements.append(analysis_table)
    elements.append(Spacer(1, 4))
    
    # -------------------------------------------------------------
    # SECTION 4: WHY THIS RESULT WAS GIVEN
    # -------------------------------------------------------------
    elements.append(Paragraph("4. WHY THIS RESULT WAS GIVEN", section_h2))
    
    detected_factors: List[str] = []
    
    if is_phishing or phish_prob >= 40.0:
        if not https_status:
            detected_factors.append("<b>Use of HTTP / Insecure Transport:</b> URL uses unencrypted plaintext HTTP protocol instead of encrypted HTTPS.")
        if subdomain_count >= 2:
            detected_factors.append(f"<b>Suspicious Domain Structure:</b> URL employs {subdomain_count} nested subdomain levels to impersonate genuine hostnames.")
        if suspicious_kw_count > 0:
            words_str = f" ('{', '.join(detected_words)}')" if detected_words else ""
            detected_factors.append(f"<b>Suspicious Keywords Detected:</b> Found {suspicious_kw_count} sensitive credential/security keyword(s){words_str} in the URL.")
        if ip_address:
            detected_factors.append(f"<b>IP Address Host Usage:</b> Destination uses a numeric IP address directly (<code>{scan.domain}</code>), bypassing standard DNS registration.")
        if has_prefix_suffix:
            detected_factors.append("<b>Hyphenated Brand Spoofing:</b> Domain structure contains deceptive brand combinations (combosquatting).")
        if has_at_symbol:
            detected_factors.append("<b>RFC-1738 @ Delimiter Redirection:</b> URL uses an '@' character to manipulate browser target resolution.")
        if has_double_slash:
            detected_factors.append("<b>Double Slash (//) Redirection:</b> Path contains irregular double-slash sequences used in phishing redirects.")
        if is_shortened:
            detected_factors.append("<b>URL Shortener Service:</b> Destination is obfuscated behind a URL redirection service.")
        if tld_risk >= 0.6:
            detected_factors.append("<b>High-Risk Top-Level Domain:</b> Registered under a TLD frequently associated with spam and automated phishing campaigns.")
        if entropy_val >= 4.2:
            detected_factors.append(f"<b>Unusual URL Characteristics (Entropy {entropy_val:.2f}):</b> Elevated randomness indicates algorithmic domain generation.")
        if not detected_factors:
            detected_factors.append("<b>Unusual URL Characteristics:</b> Lexical pattern matches trained phishing signatures.")
    else:
        detected_factors.append("<b>Secure HTTPS Encryption:</b> Operates over encrypted HTTPS protocol with standard transport security.")
        detected_factors.append("<b>Canonical Domain Structure:</b> Clean domain hierarchy without deceptive subdomain stacking or hyphenated combosquatting.")
        detected_factors.append("<b>No Suspicious Keywords:</b> Zero credential theft, spoofing, or authentication bait keywords detected.")
        detected_factors.append("<b>Standard URL Characteristics:</b> Balanced character entropy and standard lexical length aligning with verified legitimate web domains.")
        detected_factors.append("<b>Established Top-Level Domain:</b> Registered under a reputable, standard Top-Level Domain with standard DNS infrastructure.")

    # Format factor bullets inside a clean box
    factor_elements = [
        Paragraph(f"<b>Main Factors Influencing Decision ({len(detected_factors)} Detected):</b>", ParagraphStyle('FactorH', fontName='Helvetica-Bold', fontSize=7.5, leading=10, textColor=colors.HexColor('#991B1B' if is_phishing else '#166534'), spaceAfter=2))
    ]
    for f in detected_factors:
        factor_elements.append(Paragraph(f"• {f}", ParagraphStyle('FactorItem', parent=body_text, fontSize=7.5, leading=9.5, spaceAfter=1.5)))
        
    factors_box_data = [[factor_elements]]
    factors_table = Table(factors_box_data, colWidths=[540])
    factors_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#FEF2F2' if is_phishing else '#F0FDF4')),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#EF4444' if is_phishing else '#22C55E')),
        ('PADDING', (0, 0), (-1, -1), 4.5),
    ]))
    elements.append(factors_table)
    
    # -------------------------------------------------------------
    # PAGE 2: EXPLAINABLE AI, RECOMMENDATIONS, SUMMARY
    # -------------------------------------------------------------
    elements.append(PageBreak())
    
    # -------------------------------------------------------------
    # SECTION 5: EXPLAINABLE AI SUMMARY
    # -------------------------------------------------------------
    elements.append(Paragraph("5. EXPLAINABLE AI SUMMARY", section_h2))
    elements.append(Paragraph(
        "Concise mathematical summary of the top 3–5 features from Explainable AI (SHAP & LIME) influencing the model's decision:",
        subtitle_style
    ))
    
    xai_rows = [
        [
            Paragraph("Rank", table_header_style),
            Paragraph("Influential Feature", table_header_style),
            Paragraph("Observed Value", table_header_style),
            Paragraph("Risk Impact Direction", table_header_style),
            Paragraph("Short Impact Explanation", table_header_style)
        ]
    ]
    
    shap_contributions = []
    if scan.shap_summary and isinstance(scan.shap_summary, dict) and "contributions" in scan.shap_summary:
        shap_contributions = scan.shap_summary["contributions"][:5]
        
    if shap_contributions:
        for idx, item in enumerate(shap_contributions, 1):
            contrib = float(item.get("contribution", 0.0))
            is_inc = contrib > 0
            dir_text = "<font color='#DC2626'><b>+Risk (Pushed Phishing)</b></font>" if is_inc else "<font color='#16A34A'><b>-Risk (Pushed Safe)</b></font>"
            exp_text = item.get("description") or item.get("explanation") or (f"Shifted risk probability by {contrib:+.3f}")
            
            xai_rows.append([
                Paragraph(f"#{idx}", table_cell_bold),
                Paragraph(item.get("display_name", item.get("feature_name", "Feature")), table_cell_bold),
                Paragraph(str(item.get("value", "N/A")), table_cell_style),
                Paragraph(dir_text, table_cell_style),
                Paragraph(exp_text, table_cell_style)
            ])
    else:
        # Fallback based on computed features
        fallback_top = [
            ("HTTPS Protocol", "Yes" if https_status else "No", "-Risk (Pushed Safe)" if https_status else "+Risk (Pushed Phishing)", "Valid HTTPS encryption mitigates spoofing" if https_status else "Plaintext HTTP protocol elevates deception risk"),
            ("Subdomain Hierarchy", str(subdomain_count), "+Risk (Pushed Phishing)" if subdomain_count >= 2 else "-Risk (Pushed Safe)", "Nested subdomains mimic authentic brand apex" if subdomain_count >= 2 else "Standard domain depth without excessive nesting"),
            ("Suspicious Keywords", str(suspicious_kw_count), "+Risk (Pushed Phishing)" if suspicious_kw_count > 0 else "-Risk (Pushed Safe)", "Targeted credential keywords detected" if suspicious_kw_count > 0 else "Clean path without authentication bait tokens"),
            ("Shannon Entropy", f"{entropy_val:.2f}", "+Risk (Pushed Phishing)" if entropy_val >= 4.2 else "-Risk (Pushed Safe)", "High randomness suggests automated kit" if entropy_val >= 4.2 else "Standard linguistic character distribution")
        ]
        for idx, (f_name, f_val, f_dir, f_desc) in enumerate(fallback_top, 1):
            dir_styled = f"<font color='#DC2626'><b>{f_dir}</b></font>" if "+Risk" in f_dir else f"<font color='#16A34A'><b>{f_dir}</b></font>"
            xai_rows.append([
                Paragraph(f"#{idx}", table_cell_bold),
                Paragraph(f_name, table_cell_bold),
                Paragraph(f_val, table_cell_style),
                Paragraph(dir_styled, table_cell_style),
                Paragraph(f_desc, table_cell_style)
            ])
            
    xai_table = Table(xai_rows, colWidths=[30, 110, 75, 125, 200])
    xai_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0F172A')),
        ('PADDING', (0, 0), (-1, -1), 3.5),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E1')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F8FAFC'), colors.white]),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
    ]))
    elements.append(xai_table)
    elements.append(Spacer(1, 6))
    
    # -------------------------------------------------------------
    # SECTION 6: SECURITY RECOMMENDATION
    # -------------------------------------------------------------
    elements.append(Paragraph("6. SECURITY RECOMMENDATION", section_h2))
    
    if is_phishing or risk_tier in ["High", "Critical"]:
        rec_items = [
            "<b>Do not enter username or password:</b> This URL exhibits credential harvesting patterns.",
            "<b>Do not provide personal or financial information:</b> Never enter credit card, banking, or identity data.",
            "<b>Do not download files from the URL:</b> Files hosted on this domain may contain malware or spyware.",
            "<b>Verify the domain using a trusted source:</b> Navigate to official services directly via known bookmarks or official search.",
            "<b>Close or report the suspicious page if appropriate:</b> Terminate active browser tabs and report this link to your security team."
        ]
        rec_card_bg = colors.HexColor('#FEF2F2')
        rec_card_border = colors.HexColor('#DC2626')
        rec_header_color = colors.HexColor('#991B1B')
        rec_header_title = "🚨 CRITICAL SECURITY DIRECTIVES (HIGH RISK / PHISHING DETECTED)"
    else:
        rec_items = [
            "<b>The URL appears legitimate according to the current analysis:</b> Structural, heuristic, and XAI indicators match safe web patterns.",
            "<b>Continue using normal safe-browsing practices:</b> Always confirm valid HTTPS lock indicators before logging in.",
            "<b>Do not enter sensitive information unless the domain is verified:</b> Ensure you intentionally navigated to this authentic destination."
        ]
        rec_card_bg = colors.HexColor('#F0FDF4')
        rec_card_border = colors.HexColor('#16A34A')
        rec_header_color = colors.HexColor('#166534')
        rec_header_title = "🛡️ SAFE BROWSING DIRECTIVES (LOW RISK / LEGITIMATE DETECTED)"
        
    rec_content = [
        Paragraph(f"<b><font color='{rec_header_color.hexval()}'>{rec_header_title}</font></b>", ParagraphStyle('RecH', fontName='Helvetica-Bold', fontSize=8, leading=10, spaceAfter=2))
    ]
    for r in rec_items:
        rec_content.append(Paragraph(f"• {r}", ParagraphStyle('RecBullet', parent=body_text, fontSize=7.5, leading=10, spaceAfter=1.5)))
        
    rec_table = Table([[rec_content]], colWidths=[540])
    rec_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), rec_card_bg),
        ('BOX', (0, 0), (-1, -1), 0.75, rec_card_border),
        ('PADDING', (0, 0), (-1, -1), 4.5),
    ]))
    elements.append(rec_table)
    elements.append(Spacer(1, 6))
    
    # -------------------------------------------------------------
    # SECTION 7: SHORT SECURITY SUMMARY
    # -------------------------------------------------------------
    elements.append(Paragraph("7. SHORT SECURITY SUMMARY", section_h2))
    
    if is_phishing:
        main_reason = f"Detected {len(detected_factors)} risk factors: {'Insecure HTTP, ' if not https_status else ''}{'Credential keywords, ' if suspicious_kw_count > 0 else ''}{'Nested subdomains, ' if subdomain_count >= 2 else ''}Malicious pattern matching (Phishing Probability: {phish_prob:.1f}%)."
        action_text = "DO NOT PROCEED. Do not enter passwords or submit sensitive details."
    elif risk_tier == "Medium":
        main_reason = "Non-standard URL characteristics detected requiring manual caution."
        action_text = "EXERCISE CAUTION. Manually verify domain authenticity before proceeding."
    else:
        main_reason = "Clean lexical structure, verified HTTPS encryption, and standard domain hierarchy."
        action_text = "PROCEED SAFELY with standard browsing vigilance."
        
    sum_data = [
        [
            Paragraph("<b>URL:</b>", table_cell_bold),
            Paragraph(f"{scan.url}", mono_url_style),
            Paragraph("<b>Risk:</b>", table_cell_bold),
            Paragraph(f"<b><font color='{v_text_color.hexval()}'>{risk_tier.upper()}</font></b>", table_cell_style)
        ],
        [
            Paragraph("<b>Verdict:</b>", table_cell_bold),
            Paragraph(f"<b><font color='{v_text_color.hexval()}'>{prediction_label.upper()}</font></b>", table_cell_style),
            Paragraph("<b>Confidence:</b>", table_cell_bold),
            Paragraph(f"<b>{conf_score:.1f}%</b> (Phishing: {phish_prob:.1f}%)", table_cell_style)
        ],
        [
            Paragraph("<b>Main Reason:</b>", table_cell_bold),
            Paragraph(main_reason, table_cell_style),
            Paragraph("<b>Recommended Action:</b>", table_cell_bold),
            Paragraph(f"<b><font color='{v_text_color.hexval()}'>{action_text}</font></b>", table_cell_style)
        ]
    ]
    
    sum_table = Table(sum_data, colWidths=[90, 180, 100, 170])
    sum_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F8FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.75, colors.HexColor('#0F172A')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'TOP')
    ]))
    elements.append(sum_table)
    
    # Build Document with NumberedCanvas
    doc.build(elements, canvasmaker=NumberedCanvas)
    return str(file_path)


@router.get("/pdf/{scan_id}")
def download_scan_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    scan = db.query(URLScan).filter(URLScan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    # Enforce data isolation: verify user ownership
    if current_user and current_user.role != "admin" and scan.user_id is not None and scan.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied: You do not have permission to download another user's audit report.")
        
    features = db.query(URLFeatures).filter(URLFeatures.scan_id == scan_id).first()
    
    pdf_path = generate_pdf_report(scan, features)
    
    # Clean domain slug for filename
    clean_domain = "".join(c if c.isalnum() or c in ".-_" else "_" for c in (scan.domain or "scan"))
    report_filename = f"PhishGuard_Audit_Report_{clean_domain}_{scan.id}.pdf"
    
    # Save Report record in DB
    report = Report(
        user_id=current_user.id if current_user else None,
        scan_id=scan.id,
        report_name=report_filename,
        report_path=pdf_path,
        format="PDF",
        summary=f"Security Audit of {scan.url}: {scan.prediction} ({scan.phishing_probability:.1f}%)"
    )
    db.add(report)
    db.commit()
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=report_filename,
        headers={
            "Content-Disposition": f'attachment; filename="{report_filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition"
        }
    )


@router.get("/export-csv")
def export_scan_history_csv(
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    query = db.query(URLScan)
    if current_user and current_user.role != "admin":
        query = query.filter(URLScan.user_id == current_user.id)
        
    scans = query.order_by(URLScan.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Scan ID", "URL", "Domain", "Prediction", "Phishing Probability (%)",
        "Confidence Score (%)", "Risk Level", "Model Name", "Scan Timestamp"
    ])
    
    for s in scans:
        writer.writerow([
            s.id, s.url, s.domain, s.prediction, s.phishing_probability,
            s.confidence_score, s.risk_level, s.model_name, s.created_at.isoformat()
        ])
        
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=phishguard_scans_{datetime.date.today()}.csv"}
    )
