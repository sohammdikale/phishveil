````markdown
# 🛡️ Phishveil

### Think before you click.

Phishveil is a machine-learning-based phishing website detection system that analyzes website URLs and predicts whether they are likely to be **Legitimate** or **Phishing**.

The project combines **Python, Flask, URL feature extraction, and a LightGBM classification model** to provide a simple and user-friendly security assessment.

---

## ✨ Features

- 🔍 **URL Scanning** — Analyze a website URL through a simple interface.
- 🧠 **Machine Learning Detection** — Uses a trained LightGBM classification model.
- 📊 **Phishing Probability** — Displays the estimated probability of a URL being phishing.
- 🎯 **Model Confidence** — Shows the confidence associated with the prediction.
- 🚦 **Risk Classification** — Categorizes results as Safe, Suspicious, or Dangerous.
- 💡 **Detection Reasons** — Provides understandable reasons behind the assessment.
- 🔐 **HTTPS Analysis** — Checks whether the website uses HTTPS.
- 🌐 **IP Address Detection** — Identifies URLs using an IP address instead of a normal domain.
- 🔗 **URL Shortener Detection** — Detects commonly used URL-shortening services.
- 🧩 **Subdomain Analysis** — Checks for unusually deep subdomain structures.
- ⚠️ **Phishing Keyword Detection** — Identifies account and verification-related terms.
- 🌍 **Suspicious TLD Detection** — Checks potentially suspicious top-level domains.
- 🔤 **Punycode Detection** — Identifies Punycode in hostnames.
- 🔑 **Login Form Analysis** — Checks for login-form indicators.
- 🖼️ **External Resource Analysis** — Checks external favicon and webpage resources.
- 📱 **Responsive Interface** — Designed for a clean and accessible user experience.

---

## 🧠 How It Works

Phishveil follows a feature-based machine learning pipeline:

```text
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
          ┌─────────┴─────────┐
          ▼                   ▼
    📈 Probability       🎯 Prediction
          │                   │
          └─────────┬─────────┘
                    ▼
             🚦 Risk Assessment
                    │
                    ▼
             🛡️ Phishveil Result
````

---

## 🔎 Detection Indicators

Phishveil analyzes multiple characteristics of a URL and webpage rather than relying on a single indicator.

| Indicator            | Purpose                                            |
| -------------------- | -------------------------------------------------- |
| 🔐 HTTPS             | Checks whether HTTPS is used                       |
| 🌐 IP Address        | Detects IP-based hostnames                         |
| 🔗 URL Shortening    | Identifies URL-shortening services                 |
| 🧩 Subdomains        | Checks the number of subdomains                    |
| ⚠️ Phishing Hints    | Looks for suspicious account or verification terms |
| 🌍 Suspicious TLD    | Checks potentially suspicious top-level domains    |
| 🔤 Punycode          | Detects Punycode hostnames                         |
| 🔑 Login Form        | Checks for login-form presence                     |
| 🖼️ External Favicon | Checks externally hosted favicon resources         |

---

## 🤖 Machine Learning Model

Phishveil uses a **LightGBM Classifier** for phishing website classification.

The trained model is stored in:

```text
phishing_model.pkl
```

The corresponding model feature-column information is stored in:

```text
model_columns.pkl
```

The backend verifies that the feature extractor's feature order matches the feature order expected by the trained model.

### 📊 Model Output

The application generates:

* 🎯 Prediction
* 📈 Confidence
* 🚨 Phishing Probability
* 🚦 Risk Level
* 💡 Detection Reasons

---

## 🚦 Risk Classification

Phishveil converts the phishing probability into three risk levels:

| Risk Level        | Phishing Probability |
| ----------------- | -------------------: |
| 🟢 **Safe**       |        Less than 35% |
| 🟡 **Suspicious** | 35% to less than 70% |
| 🔴 **Dangerous**  |        70% or higher |

---

## 🖥️ Application Workflow

### 1️⃣ Enter a URL

Enter the website URL you want to analyze.

### 2️⃣ 🔍 Scan the URL

Phishveil extracts URL and webpage-related features.

### 3️⃣ 🧠 Machine Learning Analysis

The extracted features are passed to the trained LightGBM model.

### 4️⃣ 📊 View the Result

The application displays:

* Prediction
* Risk level
* Confidence
* Phishing probability
* Detection reasons

---

## 🏗️ Project Architecture

```text
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
          🎯 Prediction         📈 Probability
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

```text
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

### 🐍 Backend

* Python
* Flask
* LightGBM
* Joblib
* NumPy

### 🎨 Frontend

* HTML
* CSS
* JavaScript

### 🧠 Machine Learning

* Supervised Classification
* Feature Extraction
* Probability-based Prediction
* LightGBM Classification

---

## 🔌 API

Phishveil provides a Flask API endpoint for URL scanning.

### `POST /api/scan`

#### Request

```json
{
  "url": "https://example.com"
}
```

#### Response

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

> The actual values depend on the URL being analyzed and the trained model's prediction.

---

## 🌐 Flask Routes

| Method | Route       | Purpose                 |
| ------ | ----------- | ----------------------- |
| `GET`  | `/`         | Main scanning interface |
| `GET`  | `/about`    | Project information     |
| `POST` | `/api/scan` | Analyze a submitted URL |

---

## 🚀 Installation & Setup

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/sohammdikale/phishveil.git
```

### 2️⃣ Navigate to the Project

```bash
cd phishveil
```

### 3️⃣ Create a Virtual Environment

```bash
python -m venv .venv
```

### 4️⃣ Activate the Virtual Environment

#### Windows PowerShell

```powershell
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks script execution:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate again:

```powershell
.\.venv\Scripts\Activate.ps1
```

### 5️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 6️⃣ Run the Application

```bash
python app.py
```

### 7️⃣ Open in Browser

```text
http://127.0.0.1:5000
```

---

## 🧪 Testing

Phishveil can be tested with legitimate URLs and verified phishing URLs.

For legitimate website testing, examples include:

* Google
* GitHub
* Microsoft
* Apple
* Amazon
* OpenAI

For phishing testing, use verified security resources rather than manually opening suspicious URLs.

### 🔐 Useful Security Resources

* [https://phishtank.org/](https://phishtank.org/)
* [https://www.virustotal.com/](https://www.virustotal.com/)
* [https://transparencyreport.google.com/safe-browsing/](https://transparencyreport.google.com/safe-browsing/)

> ⚠️ **Never open a suspicious phishing URL directly in your normal browser.**

---

## 📊 Model Evaluation

The prediction generated by Phishveil should be treated as a **machine learning assessment**, not an absolute security guarantee.

Recommended evaluation metrics include:

* Accuracy
* Precision
* Recall
* F1-Score
* Confusion Matrix
* ROC-AUC

---

## ⚠️ Limitations

Phishveil is an academic and portfolio project and has several limitations:

* A machine learning prediction is not a guarantee of website safety.
* Legitimate websites may occasionally receive a suspicious prediction.
* Phishing websites can change their characteristics over time.
* Website content and external resources may not always be available for analysis.
* Model performance depends on the quality and distribution of its training data.
* Sophisticated phishing websites may evade detection.

### 🛑 Security Disclaimer

**Never enter passwords, payment information, or other sensitive information based solely on the result provided by Phishveil.**

Phishveil is intended for **educational, research, and demonstration purposes**.

---

## 🔮 Future Improvements

* 📈 Improve model accuracy and probability calibration
* 🧪 Use larger and more diverse phishing datasets
* 🌐 Integrate real-time threat intelligence
* 🔗 Add redirect-chain analysis
* 🏷️ Add domain reputation analysis
* 🔐 Add SSL/TLS certificate analysis
* 🌍 Add WHOIS and domain-age analysis
* 📊 Add a model performance dashboard
* 🧪 Add automated testing with verified phishing datasets
* 🌐 Develop a browser extension
* ☁️ Deploy the application for public access
* 📱 Further improve the mobile experience

---

## 🎓 Project Purpose

Phishveil was developed as an **academic and portfolio project** to explore the application of machine learning and web technologies to cybersecurity.

### 💡 Concepts Demonstrated

* 🤖 Machine Learning
* 🔐 Cybersecurity
* 🐍 Python
* 📊 Feature Engineering
* 🧠 Classification
* 🌐 Web Development
* 🌶️ Flask API Development
* 🎨 Frontend Development

---

## 👨‍💻 Author

### **Soham Dikale**

🎓 B.Tech — Artificial Intelligence & Data Science

🔗 **GitHub:**
[https://github.com/sohammdikale](https://github.com/sohammdikale)

🔗 **Project Repository:**
[https://github.com/sohammdikale/phishveil](https://github.com/sohammdikale/phishveil)

---

## ⭐ Support

If you find **Phishveil** interesting or useful, consider giving the repository a ⭐ on GitHub.

---

<div align="center">

# 🛡️ Phishveil

### Think before you click.

**Stay alert. Stay secure.**

</div>
```
