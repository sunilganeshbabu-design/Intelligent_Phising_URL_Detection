import requests

BASE = 'http://127.0.0.1:8000/api'

print('[1] Testing Auth...')
login_res = requests.post(f'{BASE}/auth/login', json={'username_or_email': 'admin@phishguard.ai', 'password': 'Admin@123'})
assert login_res.status_code == 200, f'Login failed: {login_res.text}'
token = login_res.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}
print('    Auth success! Admin token acquired.')

print('[2] Testing Single URL Predict & XAI...')
pred_res = requests.post(
    f'{BASE}/predict', 
    json={'url': 'http://paypal-security-update.account-verify.xyz/signin.php?user=test', 'model_name': 'XGBoost', 'include_xai': True}, 
    headers=headers
)
assert pred_res.status_code == 200, f'Predict failed: {pred_res.text}'
data = pred_res.json()
print(f"    URL: {data['url']} -> {data['prediction']} ({data['phishing_probability']}%)")
print(f"    SHAP Base: {data['shap_explanation']['base_value']}, Contributions: {len(data['shap_explanation']['contributions'])}")
print(f"    LIME Contributions: {len(data['lime_explanation']['contributions'])}")
print(f"    Threat Intel: {data['threat_intel']['ssl_issuer']}")
scan_id = data['id']

print('[3] Testing Bulk Predict...')
bulk_res = requests.post(f'{BASE}/predict/bulk', json={'urls': ['https://google.com', 'http://192.168.1.1/login.php', 'https://github.com']}, headers=headers)
assert bulk_res.status_code == 200, f'Bulk failed: {bulk_res.text}'
print(f"    Bulk processed: {bulk_res.json()['total_processed']}, Phishing: {bulk_res.json()['phishing_count']}")

print('[4] Testing History...')
hist_res = requests.get(f'{BASE}/history', headers=headers)
assert hist_res.status_code == 200
print(f"    Total history records: {hist_res.json()['total']}")

print('[5] Testing PDF Report Generation...')
pdf_res = requests.get(f'{BASE}/reports/pdf/{scan_id}', headers=headers)
assert pdf_res.status_code == 200, f'PDF generation failed: {pdf_res.text}'
assert pdf_res.content.startswith(b'%PDF'), 'Not a valid PDF document'
print(f"    PDF Report successfully generated ({len(pdf_res.content)} bytes, header: %PDF)")

print('[6] Testing CSV Export...')
csv_res = requests.get(f'{BASE}/reports/export-csv', headers=headers)
assert csv_res.status_code == 200
assert 'Scan ID,URL,Domain' in csv_res.text
print(f"    CSV Export valid!")

print('[7] Testing Dashboard Metrics...')
dash_res = requests.get(f'{BASE}/dashboard')
assert dash_res.status_code == 200
print(f"    Dashboard Scans: {dash_res.json()['total_scans']}, Phish %: {dash_res.json()['phishing_percentage']}%")

print('[8] Testing AI Cybersecurity Chatbot...')
bot_res = requests.post(f'{BASE}/chatbot', json={
    'message': 'Why was this URL flagged as phishing?',
    'scanned_url_context': 'http://paypal-security-update.account-verify.xyz/signin.php',
    'prediction_context': {'prediction': 'Phishing', 'phishing_probability': 85.0, 'key_factors': ['High-risk TLD', 'Subdomains']}
})
assert bot_res.status_code == 200
clean_snippet = bot_res.json()['reply'].encode('ascii', 'ignore').decode('ascii')[:90].replace('\n', ' ')
print(f"    AI Bot Reply snippet: {clean_snippet}...")

print('[9] Testing Admin System Health...')
health_res = requests.get(f'{BASE}/admin/system-health', headers=headers)
assert health_res.status_code == 200
print(f"    System Health: {health_res.json()['status']}, Models Online: {health_res.json()['models_online']}")

print('\n*** ALL 9 SYSTEM ENDPOINTS AND XAI MODULES FUNCTIONING FLAWLESSLY! ***')
