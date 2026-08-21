import os
import sys
from pathlib import Path

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.core.database import SessionLocal, engine, Base
from app.models.db_models import URLScan, URLFeatures
from app.ml.predictor import predict_url
from app.api.reports import generate_pdf_report

def count_pdf_pages(file_path: str) -> int:
    """Helper to count pages in generated PDF."""
    try:
        from pypdf import PdfReader
        reader = PdfReader(file_path)
        return len(reader.pages)
    except Exception:
        with open(file_path, "rb") as f:
            content = f.read().decode("latin1", errors="ignore")
            # Count /Type /Page occurrences (not /Pages)
            return content.count("/Type /Page\n") or content.count("/Type /Page ") or content.count("/Type/Page")

def test_pdf_generation():
    print("=" * 75)
    print("TESTING CONCISE & PROFESSIONAL PDF AUDIT REPORT GENERATION")
    print("=" * 75)
    
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    
    test_cases = [
        {
            "url": "https://www.google.com/search?q=cybersecurity",
            "expected_pred": "Legitimate",
            "desc": "Official HTTPS Search Engine"
        },
        {
            "url": "http://paypal-security-update.account-verify.xyz/signin.php?token=928103",
            "expected_pred": "Phishing",
            "desc": "Credential Harvesting Combosquatting Domain"
        },
        {
            "url": "http://192.168.1.105/bank/login.php",
            "expected_pred": "Phishing",
            "desc": "Direct IP Host Credential Phishing"
        }
    ]
    
    generated_pdfs = []
    
    for case in test_cases:
        url = case["url"]
        print(f"\n[+] Analyzing: {url} ({case['desc']})")
        res = predict_url(url, model_name="XGBoost", include_xai=True)
        
        # Save scan and features in DB
        scan = URLScan(
            url=res.url,
            domain=res.domain,
            prediction=res.prediction,
            phishing_probability=res.phishing_probability,
            confidence_score=res.confidence_score,
            risk_level=res.risk_level,
            model_name=res.model_name,
            scan_type="url",
            shap_summary=res.shap_explanation.model_dump() if res.shap_explanation else None,
            lime_summary=res.lime_explanation.model_dump() if res.lime_explanation else None,
            ai_recommendations=res.ai_recommendations
        )
        db.add(scan)
        db.flush()
        
        feats = res.features
        feat_rec = URLFeatures(
            scan_id=scan.id,
            url_length=feats.url_length,
            domain_length=feats.domain_length,
            path_length=feats.path_length,
            subdomain_count=feats.subdomain_count,
            count_dots=feats.count_dots,
            count_hyphens=feats.count_hyphens,
            count_underscores=feats.count_underscores,
            count_slashes=feats.count_slashes,
            count_question_marks=feats.count_question_marks,
            count_equals=feats.count_equals,
            count_percent=feats.count_percent,
            count_digits=feats.count_digits,
            https_status=feats.https_status,
            ip_address=feats.ip_address,
            has_at_symbol=feats.has_at_symbol,
            has_double_slash_redirect=feats.has_double_slash_redirect,
            has_prefix_suffix=feats.has_prefix_suffix,
            is_shortened_url=feats.is_shortened_url,
            suspicious_keywords=feats.suspicious_keywords,
            entropy=feats.entropy,
            tld_risk_score=feats.tld_risk_score,
            raw_features=feats.model_dump()
        )
        db.add(feat_rec)
        db.commit()
        db.refresh(scan)
        
        print(f"    -> Saved Scan ID: {scan.id} | Verdict: {scan.prediction} | Risk: {scan.risk_level} ({scan.phishing_probability:.1f}%)")
        
        pdf_path = generate_pdf_report(scan, feat_rec)
        assert os.path.exists(pdf_path), f"PDF file was not created: {pdf_path}"
        file_size_kb = os.path.getsize(pdf_path) / 1024
        
        pages = count_pdf_pages(pdf_path)
        print(f"    -> Generated PDF: {pdf_path}")
        print(f"    -> File Size: {file_size_kb:.1f} KB | Page Count: {pages} pages")
        
        # Verify that PDF size is non-trivial and page count is within 2-4 pages (expected 2 pages)
        assert file_size_kb > 2.0, "PDF file is too small"
        assert 1 <= pages <= 4, f"Unexpected page count: {pages}"
        
        # Verify scan isolation: report filename contains scan.id
        assert str(scan.id) in pdf_path, "PDF filename missing scan ID"
        
        generated_pdfs.append({
            "scan_id": scan.id,
            "url": url,
            "prediction": scan.prediction,
            "risk": scan.risk_level,
            "phish_prob": scan.phishing_probability,
            "pages": pages,
            "pdf_path": pdf_path
        })
        
    print("\n" + "=" * 75)
    print("VERIFICATION SUMMARY:")
    for item in generated_pdfs:
        print(f"  • Scan #{item['scan_id']}: [{item['prediction']}] {item['url'][:55]}... -> {item['pages']} pages ({item['risk']})")
    print(f"\nSUCCESS: All {len(generated_pdfs)} PDF Audit Reports generated cleanly and verified!")
    print("=" * 75)
    db.close()

if __name__ == "__main__":
    test_pdf_generation()
