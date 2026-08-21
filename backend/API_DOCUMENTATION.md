# 🛡️ Intelligent Phishing Detection & Threat Intelligence System
## Model & API Architecture Documentation

This documentation details the **Machine Learning Models, Internal Framework APIs, External Network Protocols, and REST API Endpoints** powering the four core detection modules:

1. 🔍 **URL Scanner Model & API** (`POST /api/predict`)
2. 📧 **Email Phishing Scanner Model & API** (`POST /api/email-scan`)
3. 📱 **QR Code Quishing Scanner Model & API** (`POST /api/predict` via `jsQR`)
4. 🌐 **Threat Intelligence & IOC Lookup Model & API** (`GET /api/threat-lookup`)

---

## 📑 Quick Navigation & API Summary

| Module | Core Models / Classifiers Used | Internal Model APIs (Libraries) | External / Protocol APIs Used | REST Endpoint |
| :--- | :--- | :--- | :--- | :--- |
| **1. URL Scanner** | • XGBooster Classifier (Primary) | • `xgboost.XGBClassifier`<br>• `shap.TreeExplainer`<br>• `lime.lime_tabular.LimeTabularExplainer`<br>• `joblib.load()` / `joblib.dump()` | • Python `urllib.parse`<br>• Shannon Entropy Calculator | `POST /api/predict` |
| **2. Email Scanner** | • Brand Typosquatting Matcher<br>• Heuristic Risk Scoring Engine<br>• Disposable Mailbox Filter | • Regex Lexical Tokenizer<br>• Shannon Mailbox Entropy Engine<br>• Brand Knowledge Graph | • `dnspython` (`dns.resolver.Resolver`) for Live `MX`, `SPF`, `DMARC` records | `POST /api/email-scan` |
| **3. QR Quishing** | • Computer Vision QR Matrix Decoder<br>• XGBooster Classifier | • `jsQR` Engine (`HTML5 Canvas API`)<br>• URL Lexical Feature Extractor<br>• `shap.TreeExplainer` | • Camera MediaDevices Stream API<br>• Image FileReader API | `POST /api/predict`<br>*(with `scan_type: "qr"`)* |
| **4. Threat IOC** | • Threat Scoring Model (0–100)<br>• Real-time Blacklist Feed Correlator | • Socket TLS Engine<br>• Cryptographic x509 Parser<br>• IOC Threat Categorizer | • `dns.resolver.Resolver` (A, AAAA, MX, NS, TXT)<br>• `ssl` & `cryptography.x509` Handshake<br>• ICANN RDAP REST API (`https://rdap.org`) | `GET /api/threat-lookup` |

---

## 1. 🔍 URL Scanner: Models & APIs

### A. What APIs & Models Does the URL Scanner Use?
1. **Machine Learning Model APIs (`xgboost`)**:
   - `xgboost.XGBClassifier`: 100 gradient boosted decision trees with logloss optimization, trained on 20+ lexical, structural, and entropy features.
   - `sklearn.preprocessing.StandardScaler`: Normalizes feature distributions across length, counts, and entropy.
2. **Explainable AI (XAI) Model APIs (`shap` & `lime`)**:
   - `shap.TreeExplainer(model)`: Calculates exact Shapley values ($S_i$) determining how each individual URL feature pushed the prediction toward **Phishing** or **Legitimate**.
   - `lime.lime_tabular.LimeTabularExplainer`: Generates local linear surrogate approximations.
3. **Data Serialization API (`joblib`)**:
   - `joblib.load()`: Loads pre-compiled binary model weights into server memory for sub-10ms inference.

---

### B. How the URL Scanner Works:
```
[Target URL] 
     │
     ▼
[1. Lexical Feature Extractor] ──► Extracts 20 numeric dimensions (Length, Dots, Hyphens, Entropy, TLD Risk, HTTPS, Keywords)
     │
     ▼
[2. Random Forest Classifier]  ──► Evaluates decision trees & outputs Phishing Probability (0.0% to 100.0%)
     │
     ▼
[3. SHAP & LIME XAI Engine]    ──► Calculates mathematical feature contributions (e.g. +28% due to Suspicious Keywords)
     │
     ▼
[4. Automated SOC Recommendations] ──► Generates tailored defensive mitigation guidance for analysts
```

---

### C. Live URL Examples & API Request/Response

#### 🔴 Phishing URL Example:
* **Target URL**: `http://paypal-verification-security-login.xyz/update-account?user=victim`

**Request**:
```bash
curl -X POST "http://127.0.0.1:8000/api/predict" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "http://paypal-verification-security-login.xyz/update-account?user=victim",
       "model_name": "Random Forest",
       "include_xai": true,
       "scan_type": "url"
     }'
```

**Response**:
```json
{
  "id": 92,
  "url": "http://paypal-verification-security-login.xyz/update-account?user=victim",
  "domain": "paypal-verification-security-login.xyz",
  "prediction": "Phishing",
  "phishing_probability": 96.4,
  "confidence_score": 96.4,
  "risk_level": "Critical",
  "model_name": "Random Forest",
  "scan_type": "url",
  "features": {
    "url_length": 72,
    "domain_length": 39,
    "count_dots": 1,
    "count_hyphens": 4,
    "https_status": false,
    "suspicious_keywords": 4,
    "entropy": 4.12,
    "tld_risk_score": 0.85,
    "detected_tld": "xyz"
  },
  "shap_explanation": {
    "base_value": 0.50,
    "prediction_value": 0.964,
    "top_contributions": [
      {
        "feature_name": "suspicious_keywords",
        "display_name": "Suspicious Security Keywords (4)",
        "value": 4,
        "contribution": 0.28,
        "direction": "phishing"
      },
      {
        "feature_name": "tld_risk_score",
        "display_name": "High-Risk Suspicious TLD (.xyz)",
        "value": 0.85,
        "contribution": 0.24,
        "direction": "phishing"
      }
    ]
  },
  "ai_recommendations": [
    "DO NOT enter credentials on this page.",
    "Block domain 'paypal-verification-security-login.xyz' at DNS sinkhole.",
    "Domain contains 4 deceptive brand keywords (paypal, verification, security, login)."
  ]
}
```

#### 🟢 Legitimate URL Example:
* **Target URL**: `https://github.com/explore`
* **Result**: **Legitimate** (2.1% Risk, Verified HTTPS, High-credibility TLD `.com`).

---

## 2. 📧 Email Scanner: Models & APIs

### A. What APIs & Models Does the Email Scanner Use?
1. **Network DNS Protocol API (`dnspython`)**:
   - `dns.resolver.Resolver()`: Connects to authoritative DNS servers over UDP/TCP port 53.
   - Resolves `MX` (Mail Exchanger) records to determine if the destination server can receive valid emails.
   - Queries `TXT` records to validate Sender Policy Framework (`v=spf1`) and DMARC (`_dmarc`) email authentication policies.
2. **Brand Typosquatting Knowledge Engine**:
   - Compares the sender mailbox username against 30+ monitored global brands (`PayPal`, `Apple`, `Chase`, `Google`, `Amazon`, `Microsoft`, `Netflix`, `Meta`, `Binance`, `IRS`, `FedEx`, `USPS`, etc.).
3. **Disposable Inbox Classification Engine**:
   - Cross-checks against 30+ known temporary burner mailbox domains (`mailinator.com`, `tempmail.com`, `yopmail.com`, `guerrillamail.com`, etc.).
4. **Shannon Mailbox Entropy API**:
   - Computes character distribution randomness to detect automated algorithmic phishing address generation (DGA).

---

### B. How the Email Scanner Works:
```
[Sender Email Address] ──► "paypal.security-alert@service-update.xyz"
           │
           ├─► [1. RFC 5322 Lexical Parser]   ── Split: Username="paypal.security-alert", Domain="service-update.xyz"
           ├─► [2. Brand Typosquat Matcher]   ── Username claims "PayPal", Domain is NOT paypal.com ➔ Brand Spoof!
           ├─► [3. dnspython DNS Resolver]    ── Query MX (found), Query SPF (missing), Query DMARC (missing)
           ├─► [4. Disposable/Webmail Check]  ── Verified Custom Domain (not public Gmail or disposable)
           ▼
[5. XAI Heuristic Attribution Engine]
           │
           ▼
[Output: Verdict="Critical Phishing Spoof", Probability=94.2%, Attack Category="Brand Impersonation"]
```

---

### C. Live Email Examples & API Request/Response

#### 🔴 Phishing Spoof Email Example:
* **Target Email**: `paypal.security-alert@service-update.xyz`

**Request**:
```bash
curl -X POST "http://127.0.0.1:8000/api/email-scan" \
     -H "Content-Type: application/json" \
     -d '{"email": "paypal.security-alert@service-update.xyz"}'
```

**Response**:
```json
{
  "email": "paypal.security-alert@service-update.xyz",
  "username": "paypal.security-alert",
  "domain": "service-update.xyz",
  "is_valid_format": true,
  "overall_verdict": "Critical Phishing Spoof",
  "phishing_probability": 94.2,
  "risk_level": "Critical",
  "confidence_score": 95.0,
  "is_brand_spoofed": true,
  "spoofed_brand": "PayPal",
  "is_disposable": false,
  "is_free_webmail": false,
  "entropy_score": 3.75,
  "tld_risk_score": 0.85,
  "dns_info": {
    "has_mx": true,
    "primary_mx": "mail.service-update.xyz",
    "mail_provider": "Generic Mail Server",
    "has_spf": false,
    "has_dmarc": false,
    "dns_status": "Live Records Resolved"
  },
  "feature_contributions": [
    {
      "feature_name": "brand_spoofing",
      "display_name": "Brand Impersonation (PayPal)",
      "contribution": 0.35,
      "direction": "phishing",
      "description": "Username claims brand 'PayPal' while operating from unrelated domain 'service-update.xyz'."
    },
    {
      "feature_name": "high_risk_tld",
      "display_name": "High-Risk Domain TLD (.xyz)",
      "contribution": 0.25,
      "direction": "phishing",
      "description": "TLD '.xyz' exhibits elevated correlation with spam and phishing campaigns."
    }
  ],
  "threat_indicators": [
    {
      "category": "Brand Impersonation Spoof",
      "severity": "Critical",
      "detail": "Email username claims to represent 'PayPal' while operating from domain 'service-update.xyz'."
    }
  ],
  "actionable_advice": [
    "Do NOT click any invoice or verification links sent from this address.",
    "Report this sender to your SOC team as an active brand impersonation phish."
  ]
}
```

#### 🟡 Webmail Impersonation Example:
* **Target Email**: `chase.bank.fraud.dept@gmail.com`
* **Result**: **Suspicious Email Address** (78.0% Risk — Banking department claims operating from free public Google Webmail).

#### 🟢 Legitimate Corporate Email Example:
* **Target Email**: `support@github.com`
* **Result**: **Legitimate / Verified Safe** (3.0% Risk — Authenticated GitHub domain with active MX, SPF, and DMARC).

---

## 3. 📱 QR Code Quishing Scanner: Models & APIs

### A. What APIs & Models Does the QR Quishing Scanner Use?
1. **Client-Side Computer Vision API (`jsQR`)**:
   - `jsQR(imageData.data, width, height)`: Scans the raw 2D barcode pixel matrix rendered on an HTML5 `<canvas>`.
   - Locates alignment finder patterns (Position Detection Patterns), performs Reed-Solomon error correction, and extracts the raw embedded string.
2. **Camera Stream API (`navigator.mediaDevices.getUserMedia`)**:
   - Accesses live device camera video streams for real-time QR scanning.
3. **Backend ML Inference API (`POST /api/predict`)**:
   - Passes the extracted destination URL to the Random Forest model with parameter `"scan_type": "qr"`.
4. **SHAP XAI Engine (`shap.TreeExplainer`)**:
   - Generates feature attribution for the hidden target destination.

---

### B. How the QR Quishing Scanner Works:
```
[QR Code Image / Video Stream] 
              │
              ▼
[HTML5 Canvas Matrix Extractor]
              │
              ▼
[jsQR Computer Vision Decoder] ──► Decodes hidden URL: "https://login-apple-icloud-secure.top/auth"
              │
              ▼
[POST /api/predict (scan_type="qr")]
              │
              ▼
[Random Forest Inference + SHAP XAI Breakdown + Database Audit Logging]
```

---

### C. Live QR Quishing Examples & Integration Payload

* **Embedded Target URL**: `https://login-apple-icloud-secure.top/session-verify`

**API Request**:
```bash
curl -X POST "http://127.0.0.1:8000/api/predict" \
     -H "Content-Type: application/json" \
     -d '{
       "url": "https://login-apple-icloud-secure.top/session-verify",
       "model_name": "Random Forest",
       "include_xai": true,
       "scan_type": "qr"
     }'
```

**Response Verdict**:
* **Verdict**: **Phishing** (95.8% Risk)
* **Threat Tag**: Quishing / QR Phishing Intercepted
* **Identified Indicators**: Deceptive Apple ID keyword impersonation on high-risk TLD `.top`.

---

## 4. 🌐 Threat Intelligence & IOC Lookup: Models & APIs

### A. What APIs & Models Does the Threat IOC Module Use?
1. **Real-Time DNS Socket API (`dnspython`)**:
   - Performs parallel DNS resolution for `A` (IPv4), `AAAA` (IPv6), `MX` (Mail), `NS` (Nameservers), and `TXT` (Verification).
2. **Live TLS/SSL Handshake API (`ssl` & `cryptography.x509`)**:
   - Initiates an SSL/TLS socket connection on port 443.
   - Extracts Certificate Authority (CA) issuer string, validity lifespan (`valid_from` to `valid_to`), protocol version (`TLSv1.3`), and SAN names.
3. **ICANN RDAP / WHOIS REST API**:
   - Endpoint: `https://rdap.org/domain/{domain}`
   - Queries ICANN accredited registries for domain registration date, longevity age, and registrar name.
4. **Threat Reputation Scoring Model (0 to 100)**:
   - Evaluates weighted penalties for blacklisted feeds, newly registered domains (<30 days), untrusted CAs, and missing DNS infrastructure:
     $$\text{Score} = 100 - \sum(\text{Penalties})$$
     - `0 to 40`: **Critical Threat / Malicious**
     - `41 to 70`: **Medium / Suspicious**
     - `71 to 100`: **Safe / Verified**

---

### B. How Threat IOC Intelligence Works:
```
[Target Domain / IP / URL] ──► "paypal-security-update.xyz"
           │
           ├─► [1. Blacklist Feed Correlator]  ── Match found in Active Impersonation Registry
           ├─► [2. dnspython DNS Engine]       ── A: 198.51.100.45, NS: ns1.suspicious-dns.com, MX: mail...
           ├─► [3. x509 TLS Socket Handshake]  ── Issuer: Let's Encrypt, Protocol: TLSv1.3, Validity: 90 days
           ├─► [4. ICANN RDAP / WHOIS Query]   ── Created: Recently Created (High-risk window)
           ▼
[5. Reputation Index Calculator] ──► Score: 12 / 100 (Critical Risk)
```

---

### C. Live IOC Query Examples & API Request/Response

#### 🔴 Malicious Domain IOC Example:
* **Target Domain**: `paypal-security-update.xyz`

**Request**:
```bash
curl -X GET "http://127.0.0.1:8000/api/threat-lookup?query=paypal-security-update.xyz" \
     -H "Accept: application/json"
```

**Response**:
```json
{
  "query": "paypal-security-update.xyz",
  "indicator_type": "domain",
  "reputation_score": 12.0,
  "risk_level": "Critical",
  "is_blacklisted": true,
  "blacklist_sources": [
    "PhishGuard Dynamic Threat Feeds",
    "Active Impersonation Registry",
    "OpenPhish Community Telemetry"
  ],
  "whois_creation_date": "Recently Created (Active High Risk Window)",
  "whois_registrar": "NameCheap, Inc. / Privacy Protected",
  "dns_records": [
    {
      "record_type": "A",
      "value": "198.51.100.45",
      "ttl": 300
    },
    {
      "record_type": "NS",
      "value": "ns1.suspicious-dns.com",
      "ttl": 3600
    },
    {
      "record_type": "MX",
      "value": "mail.paypal-security-update.xyz",
      "ttl": 300
    }
  ],
  "ssl_details": {
    "issuer": "Let's Encrypt Authority / Free Automated CA",
    "valid_from": "2026-08-01",
    "valid_to": "2026-11-01",
    "is_trusted": true,
    "protocol": "TLSv1.3",
    "common_name": "paypal-security-update.xyz"
  },
  "historical_phishing_hits": 24,
  "threat_categories": [
    "Brand Impersonation / Credential Harvester",
    "High-Risk TLD Association"
  ],
  "security_recommendations": [
    "Block domain 'paypal-security-update.xyz' at perimeter DNS sinkholes.",
    "Add associated IP '198.51.100.45' to firewall blacklists."
  ]
}
```

#### 🟢 Authentic Legitimate IOC Example:
* **Target Domain**: `github.com`
* **Response**:
  - **Reputation Score**: **98 / 100** (Safe)
  - **Blacklist Status**: Clean / No Malicious Records
  - **SSL Issuer**: DigiCert Global Root G2 (Enterprise Commercial CA)
  - **DNS Routing**: Active Microsoft/GitHub Anycast Global DNS Network.

---

## 5. 🛠️ Interactive API Testing Access

You can test every single model and endpoint interactively in your browser:

* **Interactive Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) (Allows executing live requests directly)
* **ReDoc Technical Schema**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)
* **Frontend Web Interface**: [http://localhost:5173/](http://localhost:5173/)
