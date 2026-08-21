import sys
sys.stdout.reconfigure(encoding='utf-8')
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

print("=" * 80)
print("FASTAPI API INTEGRATION TESTS (INCLUDING UPGRADED CHATBOT)")
print("=" * 80)

# 1. Test Health / Root
res = client.get("/api/dashboard")
print(f"[1] Dashboard endpoint status: {res.status_code}")
assert res.status_code == 200

# 2. Test 10-Module Registry
res = client.get("/api/modules/registry")
print(f"[2] Module Registry status: {res.status_code} ({len(res.json().get('modules', []))} modules)")
assert res.status_code == 200
assert len(res.json().get("modules", [])) == 10

# 3. Test Prediction Endpoint
scan_payload = {
    "url": "http://paypal-security-update.account-verify.xyz/signin.php",
    "model_name": "XGBoost",
    "include_xai": True
}
res_scan = client.post("/api/predict", json=scan_payload)
print(f"[3] URL Prediction status: {res_scan.status_code}")
assert res_scan.status_code == 200
scan_data = res_scan.json()
print(f"    -> Scan ID: {scan_data.get('id')}, Verdict: {scan_data.get('prediction')}, Probability: {scan_data.get('phishing_probability')}%")

# 3b. Test PDF Audit Report Endpoint for this scan
pdf_res = client.get(f"/api/reports/pdf/{scan_data['id']}")
print(f"[3b] PDF Audit Report Download status: {pdf_res.status_code} ({len(pdf_res.content)} bytes, type: {pdf_res.headers.get('content-type')})")
assert pdf_res.status_code == 200
assert pdf_res.headers.get("content-type") == "application/pdf"
assert len(pdf_res.content) > 2000

# 4. Test Chatbot Endpoint with Live Scan Data
chat_payload = {
    "message": "Why was this URL classified as phishing?",
    "scanned_url_context": scan_data["url"],
    "prediction_context": scan_data
}
res_chat = client.post("/api/chatbot", json=chat_payload)
print(f"[4] Chatbot Scan Explanation status: {res_chat.status_code}")
assert res_chat.status_code == 200
chat_resp = res_chat.json()
lines = [l for l in chat_resp["reply"].split("\n") if l.strip()]
print(f"    -> Response Header: {lines[0] if lines else 'EMPTY'}")
print(f"    -> Length: {len(chat_resp['reply'])} chars")
assert len(chat_resp["reply"]) > 100

# 5. Test Chatbot General Question
general_chat_payload = {
    "message": "Explain the difference between phishing and malware"
}
res_gen = client.post("/api/chatbot", json=general_chat_payload)
print(f"[5] Chatbot General Q status: {res_gen.status_code}")
assert res_gen.status_code == 200
assert "Phishing vs Malware" in res_gen.json()["reply"]

# 6. Test Chatbot 10-Module Question
mod_chat_payload = {
    "message": "Explain the 10 detection modules."
}
res_mod = client.post("/api/chatbot", json=mod_chat_payload)
print(f"[6] Chatbot 10 Modules status: {res_mod.status_code}")
assert res_mod.status_code == 200
assert "Module 1" in res_mod.json()["reply"]
assert "Module 10" in res_mod.json()["reply"]

print("\n" + "=" * 80)
print("🎉 ALL FASTAPI & CHATBOT API INTEGRATION TESTS PASSED 100%!")
print("=" * 80)
