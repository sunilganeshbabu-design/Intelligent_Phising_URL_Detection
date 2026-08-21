# Intelligent Phishing URL Detection Using Explainable AI (XAI)

An enterprise-grade, full-stack cybersecurity web application that detects malicious phishing URLs using Machine Learning and provides transparent, interpretable decisions through **Explainable AI (SHAP & LIME)**.

---

## 🌟 Key Features

1. **High-Performance Machine Learning Engine**:
   - **XGBooster Classifier (Primary Engine)**: Extreme Gradient Boosted Trees with 100 estimators, max depth 6, and logloss objective delivering ~99.4% benchmark accuracy.
2. **Explainable AI (XAI) Interpretability**:
   - **SHAP (SHapley Additive exPlanations)**: Calculates directional mathematical impact (positive pushing towards phishing, negative pushing towards safe) for every feature against baseline prior.
   - **LIME (Local Interpretable Model-agnostic Explanations)**: Builds local perturbation surrogate models to expose instance-level decision boundaries.
   - **Plain-English AI Synthesis**: Translates mathematical feature weights into actionable human-friendly security summaries.
3. **Interactive XAI "What-If" Counterfactual Simulator**:
   - Live interactive sliders and toggle switches to test counterfactual scenarios (e.g. "What if I remove 3 subdomains?", "What if HTTPS is enabled?", "What if entropy is lowered?").
   - Watch the risk probability gauge and SHAP feature attributions recalculate in real-time!
4. **Phishing Email & Social Engineering Body Scanner**:
   - Paste suspicious email headers and message bodies.
   - Extracts all embedded HTTP/HTTPS URLs (including obfuscated links), detects psychological urgency/fear cues, and scores all links with Explainable AI.
5. **QR Code Phishing ("Quishing") Image Analyzer**:
   - Upload or drag-and-drop QR code images (PNG, JPG, WebP) or choose 1-click test samples.
   - Decodes embedded URLs via HTML5 Canvas and runs full XGBooster XAI analysis.
6. **Threat Intelligence & IOC Lookup Console**:
   - Search hostnames and IPv4 addresses against WHOIS age, simulated DNS routing infrastructure, SSL certificate legitimacy, and global threat blacklist feeds.
7. **20+ Feature Extraction Engine**:
   - **Lexical & Length**: URL length, domain length, path length, dot count, hyphen count, slash count, digit count.
   - **Structural & Protocol**: Nested subdomain stacking count, HTTPS encryption check, URL shortener detection (`bit.ly`, `tinyurl`).
   - **Security Heuristics**: Direct IP host evasion (`http://192.168.1.1/...`), RFC-1738 `@` symbol redirection tricks, double slash `//` redirect spoofing, prefix/suffix hyphens in brand names.
   - **Semantic & Statistical**: Suspicious keyword detector (`login`, `verify`, `banking`, `secure`, `webscr`, `account`), Shannon Entropy randomness index, Spamhaus/SURBL TLD risk factor rating (`.xyz`, `.top`, `.tk`, `.buzz`, etc.).
8. **Threat Intelligence & SSL Heuristics**:
   - Real-time matching against known malicious domain feeds, SSL issuer verification, IDN Homograph / Punycode attack detection.
9. **Interactive Cybersecurity UI (React + Vite)**:
   - **Animated SVG Risk Meter Gauge** (0–100% phishing probability).
   - **Interactive SHAP Feature Contribution Waterfall Bar Chart**.
   - **LIME Local Perturbation Rules Inspector**.
   - **Searchable 20+ Feature Extraction Table with Risk Flags**.
   - **Interactive AI Security Chatbot**: Floating assistant explaining why links were flagged and offering cyber defense tips.
   - **Bulk URL Scanner**: Batch process up to 100 URLs with summary stats and CSV export.
   - **PDF Security Audit Reports**: 1-click download of executive-styled compliance audit reports generated dynamically via ReportLab.
   - **Analytics Dashboard**: Chart.js Doughnut and Bar charts showing weekly trends, phishing ratios, and top threat targets.
   - **Admin Management Console**: User management, dataset inspector, live accuracy benchmarks, and 1-click model retraining pipeline.

---

## 🏗️ System Architecture

```
User (Browser)
       ↓
React 18 Frontend (Vite, Glassmorphic UI, Chart.js, Lucide Icons)
       ↓  (REST API / JWT Bearer)
FastAPI Backend Server
       ↓
Feature Extraction Engine (20+ Lexical, Structural & Entropy Metrics)
       ↓
Machine Learning Pipeline (XGBooster Engine)
       ↓
Explainable AI (XAI) Engine (SHAP TreeExplainer + LIME Tabular Explainer)
       ↓
Threat Intelligence & Heuristic Fusion Module
       ↓
SQLite Database (Users, URL Scans, Features, Reports, Threat Feeds)
```

---

## 🚀 Quick Start Guide

### Prerequisites
- **Python 3.10+**
- **Node.js 18+** and **npm**

---

### 1. Backend Setup & Startup

```bash
# 1. Open terminal in project root and navigate to backend
cd backend

# 2. Activate virtual environment (if not already active)
# On Windows:
..\venv\Scripts\activate

# 3. Start FastAPI Backend
python run.py
```
* Backend API documentation will be available at: **`http://127.0.0.1:8000/docs`**

---

### 2. Frontend Setup & Startup

```bash
# 1. Open a new terminal in the frontend directory
cd frontend

# 2. Start Vite React development server
npm run dev
```
* Access the web application at: **`http://127.0.0.1:5173/`**

---

## 🔑 Default Credentials

| Role | Username / Email | Password | Privileges |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@phishguard.ai` | `Admin@123` | Full access to Admin Console, Model Retraining, User Management, and all Scans |
| **Demo Analyst** | `demo@phishguard.ai` | `Demo@123` | URL Scanner, Dashboard, Scan History, PDF Reports, and AI Chatbot |

*(You can also use the 1-click Demo buttons on the Sign In page!)*

---

## 🧪 Sample Test URLs

| Type | Test URL | Expected Verdict |
| :--- | :--- | :--- |
| **Phishing (Credential Harvest)** | `http://paypal-security-update.account-verify.xyz/signin.php` | ⚠️ **Phishing (~98%)** |
| **Phishing (Direct IP Host)** | `http://192.168.1.100/login/bankofamerica-auth.php?token=928103` | ⚠️ **Phishing (~84%)** |
| **Phishing (Typosquatting)** | `http://appleid-support-validation.login-portal.top/recover` | ⚠️ **Phishing (~95%)** |
| **Legitimate (Search Engine)** | `https://www.google.com` | 🛡️ **Legitimate (0%)** |
| **Legitimate (Code Host)** | `https://github.com/torvalds/linux` | 🛡️ **Legitimate (0%)** |
| **Legitimate (Enterprise)** | `https://www.microsoft.com/en-us/security` | 🛡️ **Legitimate (0%)** |

---

## 📚 API Endpoints

- `POST /api/auth/register` — Register a new analyst account
- `POST /api/auth/login` — Sign in and receive JWT bearer token
- `GET  /api/auth/me` — Get authenticated user profile
- `POST /api/predict` — Deep URL scan with SHAP & LIME XAI
- `POST /api/predict/bulk` — Batch scan up to 100 URLs
- `GET  /api/history` — Paginated, searchable scan history
- `DELETE /api/history/{id}` — Delete scan record
- `GET  /api/reports/pdf/{id}` — Download formatted PDF audit report
- `GET  /api/reports/export-csv` — Export complete scan history as CSV
- `GET  /api/dashboard` — Overview metrics and Chart.js trend datasets
- `POST /api/chatbot` — Query the context-aware AI Security Assistant
- `GET  /api/admin/system-health` — Live model performance and runtime status
- `GET  /api/admin/dataset-stats` — Dataset samples, features, and preview
- `POST /api/admin/retrain-model` — One-click ML model retraining pipeline
- `GET  /api/admin/users` — User management and status toggle
