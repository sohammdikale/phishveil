# 🛡️ Phishveil

### Think before you click.

Phishveil is a machine-learning-based phishing website detection system that analyzes website URLs and predicts whether they are likely to be **Legitimate** or **Phishing**.

The project combines **Python, Flask, URL feature extraction, and a LightGBM classification model** to deliver a simple, user-friendly security assessment.

---

## ✨ Features

- 🔍 **URL Scanning** — Analyze any website URL through a simple interface
- 🧠 **Machine Learning Detection** — Powered by a trained LightGBM classifier
- 📊 **Phishing Probability** — Displays the estimated probability of a URL being phishing
- 🎯 **Model Confidence** — Shows confidence associated with each prediction
- 🚦 **Risk Classification** — Categorizes results as Safe, Suspicious, or Dangerous
- 💡 **Detection Reasons** — Explains the reasoning behind each assessment
- 🔐 **HTTPS Analysis** — Checks whether the site uses HTTPS
- 🌐 **IP Address Detection** — Flags URLs using an IP address instead of a domain
- 🔗 **URL Shortener Detection** — Detects common URL-shortening services
- 🧩 **Subdomain Analysis** — Flags unusually deep subdomain structures
- ⚠️ **Phishing Keyword Detection** — Identifies account/verification-related terms
- 🌍 **Suspicious TLD Detection** — Flags potentially risky top-level domains
- 🔤 **Punycode Detection** — Identifies Punycode in hostnames
- 🔑 **Login Form Analysis** — Checks for login-form indicators
- 🖼️ **External Resource Analysis** — Checks external favicon/webpage resources
- 📱 **Responsive Interface** — Clean, accessible UI across devices

---

## 🧠 How It Works

```
        🌐 Website URL
              │
              ▼
        🔍 URL Analysis
              │
              ▼
      ⚙️ Feature Extraction
              │
              ▼
       🧠 LightGBM Model
              │
     ┌────────┴────────┐
     ▼                 ▼
📈 Probability    🎯 Prediction
     │                 │
     └────────┬────────┘
              ▼
       🚦 Risk Assessment
              │
              ▼
       🛡️ Phishveil Result
```

When a user submits a URL, Phishveil extracts relevant characteristics from the URL (and, when available, the webpage). These features are passed to the trained model, which returns a prediction and probability.

---

## 🔎 Detection Indicators

| Indicator | Purpose |
|---|---|
| 🔐 HTTPS | Checks whether HTTPS is used |
| 🌐 IP Address | Detects IP-based hostnames |
| 🔗 URL Shortening | Identifies URL-shortening services |
| 🧩 Subdomains | Checks number of subdomains |
| ⚠️ Phishing Hints | Looks for suspicious account/verification terms |
| 🌍 Suspicious TLD | Checks potentially risky top-level domains |
| 🔤 Punycode | Detects Punycode hostnames |
| 🔑 Login Form | Checks for login-form presence |
| 🖼️ External Favicon | Checks externally hosted favicon resources |

---

## 🤖 Machine Learning Model

Phishveil uses a **LightGBM Classifier** for phishing detection.

- Trained model → `phishing_model.pkl`
- Feature-column metadata → `model_columns.pkl`

The backend verifies that the feature extractor's output order matches the order expected by the trained model.

### 📊 Model Output

- 🎯 Prediction
- 📈 Confidence
- 🚨 Phishing Probability
- 🚦 Risk Level
- 💡 Detection Reasons

---

## 🚦 Risk Classification

| Risk Level | Phishing Probability |
|---|---|
| 🟢 Safe | Less than 35% |
| 🟡 Suspicious | 35% to less than 70% |
| 🔴 Dangerous | 70% or higher |

---

## 🏗️ Project Architecture

```
             👤 User
               │
               ▼
        🖥️ Web Interface
               │
               ▼
          🌐 Flask API
               │
               ▼
     ⚙️ Feature Extractor
               │
               ▼
      📊 Feature Vector
               │
               ▼
       🧠 LightGBM Model
               │
    ┌──────────┴──────────┐
    ▼                     ▼
🎯 Prediction        📈 Probability
    │                     │
    └──────────┬──────────┘
               ▼
        🚦 Risk Analysis
               │
               ▼
      💡 Detection Reasons
               │
               ▼
        🛡️ Final Result
```

---

## 📁 Project Structure

```
Phishveil/
│
├── app.py
├── feature_extractor.py
├── phishing_model.pkl
├── model_columns.pkl
├── requirements.txt
├── .gitignore
│
├── templates/
│   ├── index.html
│   └── about.html
│
└── static/
    ├── style.css
    └── script.js
```

---

## ⚙️ Technology Stack

**Backend:** Python, Flask, LightGBM, Joblib, NumPy
**Frontend:** HTML, CSS, JavaScript
**Machine Learning:** Supervised Classification, Feature Extraction, Probability-based Prediction

---

## 🔌 API

### `POST /api/scan`

**Request**
```json
{
  "url": "https://example.com"
}
```

**Response**
```json
{
  "ok": true,
  "prediction": "Legitimate",
  "risk": "safe",
  "confidence": 95.0,
  "phishing_probability": 5.0,
  "details": {},
  "reasons": []
}
```

---

## 🌐 Flask Routes

| Method | Route | Purpose |
|---|---|---|
| GET | `/` | Main scanning interface |
| GET | `/about` | Project information |
| POST | `/api/scan` | Analyze a submitted URL |

---

## 🚀 Installation & Setup

**1. Clone the repository**
```bash
git clone https://github.com/sohammdikale/phishveil.git
```

**2. Navigate to the project**
```bash
cd phishveil
```

**3. Create a virtual environment**
```bash
python -m venv .venv
```

**4. Activate the virtual environment**

Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
```
If PowerShell blocks execution:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

**5. Install dependencies**
```bash
pip install -r requirements.txt
```

**6. Run the application**
```bash
python app.py
```

**7. Open in browser**
```
http://127.0.0.1:5000
```

---

## 🧪 Testing

Test with legitimate URLs (Google, GitHub, Microsoft, Apple, Amazon, OpenAI) and verified phishing URLs from trusted security resources — never open suspicious URLs directly.

**Useful security resources**
- https://phishtank.org/
- https://www.virustotal.com/
- https://transparencyreport.google.com/safe-browsing/

> ⚠️ **Never open a suspicious phishing URL directly in your normal browser.**

---

## 📊 Model Evaluation

Predictions should be treated as a machine learning assessment, not an absolute security guarantee. Recommended evaluation metrics: Accuracy, Precision, Recall, F1-Score, Confusion Matrix, ROC-AUC.

---

## ⚠️ Limitations

- A machine learning prediction is not a guarantee of website safety
- Legitimate websites may occasionally receive a suspicious prediction
- Phishing websites can change their characteristics over time
- Website content/external resources may not always be available for analysis
- Model performance depends on the quality of its training data
- Sophisticated phishing sites may evade detection

### 🛑 Security Disclaimer

**Never enter passwords, payment information, or other sensitive data based solely on Phishveil's result.** Phishveil is intended for educational, research, and demonstration purposes only.

---

## 🔮 Future Improvements

- 📈 Improve model accuracy and probability calibration
- 🧪 Use larger, more diverse phishing datasets
- 🌐 Integrate real-time threat intelligence
- 🔗 Add redirect-chain analysis
- 🏷️ Add domain reputation analysis
- 🔐 Add SSL/TLS certificate analysis
- 🌍 Add WHOIS and domain-age analysis
- 📊 Add a model performance dashboard
- 🌐 Develop a browser extension
- ☁️ Deploy the application for public access

---

## 🎓 Project Purpose

Phishveil was built as an academic and portfolio project exploring the application of machine learning and web technologies to cybersecurity — covering feature engineering, classification, Flask API development, and frontend design.

---

## 👨‍💻 Author

**Soham Dikale**
🎓 B.Tech — Artificial Intelligence & Data Science
🔗 GitHub: [github.com/sohammdikale](https://github.com/sohammdikale)
🔗 Project Repository: [github.com/sohammdikale/phishveil](https://github.com/sohammdikale/phishveil)

---

## ⭐ Support

If you find Phishveil useful, consider giving the repo a ⭐ on GitHub!

**Stay alert. Stay secure.**
