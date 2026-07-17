<div align="center">

# 🛡️ PhishGuard

### Real-Time Browser-Based Phishing Detection and Protection

PhishGuard is a Chrome browser extension connected to a Python backend that analyzes URLs, calculates a risk score, and warns users before they continue to potentially unsafe websites.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-Backend-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![JavaScript](https://img.shields.io/badge/JavaScript-Browser%20Extension-yellow?logo=javascript&logoColor=black)](https://developer.mozilla.org/docs/Web/JavaScript)
[![Chrome Extension](https://img.shields.io/badge/Chrome-Manifest%20V3-4285F4?logo=googlechrome&logoColor=white)](https://developer.chrome.com/docs/extensions/)
[![License](https://img.shields.io/badge/License-Educational-lightgrey)](#license)

</div>

---

## 📌 About the Project

PhishGuard is designed to help users identify suspicious and phishing websites directly from their browser. The browser extension sends a URL to the local FastAPI backend, where the phishing-detection engine extracts security-related features and generates a risk assessment.

Based on the result, the URL is classified as:

- ✅ **Safe**
- ⚠️ **Suspicious**
- 🚨 **Dangerous**

The extension then displays the result and can show a warning page for high-risk websites.

---

## ✨ Main Features

- Real-time URL scanning from the browser
- Automatic phishing-risk calculation
- Rule-based URL and domain analysis
- Machine-learning model support
- Risk score with feature-level explanation
- Safe, suspicious, and dangerous classifications
- Warning page for dangerous websites
- Scan history and dashboard support
- Browser notifications
- Allowlist support
- Local backend for improved privacy
- Chrome Manifest V3 architecture

---

## 🔍 Detection Parameters

PhishGuard can evaluate indicators such as:

- HTTPS availability
- URL length and structure
- Suspicious symbols and patterns
- IP address used instead of a domain
- Excessive digits in domain names
- Suspicious top-level domains
- Brand impersonation patterns
- Newly registered or risky domains
- DNS availability
- SSL certificate information
- Suspicious keywords
- Hosting and blacklist-related signals
- Machine-learning prediction

> Detection results are intended to support users and should not be treated as a replacement for professional security tools.

---

## 🏗️ System Architecture

```text
User Opens Website
        │
        ▼
Chrome Browser Extension
        │
        ▼
Background Service Worker
        │
        ▼
REST API Request
        │
        ▼
Python FastAPI Backend
        │
        ▼
Phishing Detection Engine
        │
        ▼
Risk Score and Classification
        │
        ▼
Extension Displays Result
        │
        ├── Safe → Allow Access
        ├── Suspicious → Show Caution
        └── Dangerous → Display Warning
```

---

## 🛠️ Technology Stack

### Backend

- Python
- FastAPI
- Uvicorn
- Pydantic
- Scikit-learn
- Joblib

### Browser Extension

- JavaScript
- HTML
- CSS
- Chrome Extension Manifest V3
- Chrome Storage, Tabs, Web Navigation and Notifications APIs

---

## 📁 Project Structure

```text
phishguard/
│
├── backend/
│   ├── data/
│   ├── models/
│   ├── __init__.py
│   ├── ai_model.py
│   ├── engine.py
│   ├── main.py
│   ├── requirements.txt
│   ├── test_security_verdicts.py
│   └── train_model.py
│
├── browser-extension/
│   ├── icons/
│   ├── options/
│   ├── popup/
│   ├── api_config.js
│   ├── background.js
│   ├── manifest.json
│   ├── scan_result.js
│   ├── warning.css
│   ├── warning.html
│   └── warning.js
│
├── .gitignore
├── run_backend.py
└── README.md
```

---

## ⚙️ Installation and Setup

### Prerequisites

Install the following before running the project:

- Python 3.10 or newer
- Google Chrome or another Chromium-based browser
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/adarsh8901/phishguard.git
cd phishguard
```

### 2. Create a Virtual Environment

#### Windows PowerShell

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

#### Windows Command Prompt

```cmd
python -m venv .venv
.venv\Scripts\activate
```

#### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Backend Dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Start the Backend

Run this command from the project root:

```bash
python run_backend.py
```

The backend should start at:

```text
http://127.0.0.1:8080
```

---

## 🌐 Load the Browser Extension

1. Open Google Chrome.
2. Go to `chrome://extensions/`.
3. Enable **Developer mode**.
4. Click **Load unpacked**.
5. Select the `browser-extension` folder.
6. Pin PhishGuard from the Extensions menu.
7. Keep the Python backend running while using the extension.

---

## 🚀 How to Use

1. Start the backend with `python run_backend.py`.
2. Open a website in Chrome.
3. Click the PhishGuard extension icon.
4. Scan the current URL.
5. Review the generated risk score and verdict.
6. Follow the warning shown for suspicious or dangerous websites.

---

## 🧪 Run Tests

From the project root, run:

```bash
python -m unittest backend/test_security_verdicts.py
```

---

## 🤖 Machine-Learning Model

The project includes files for training and loading a local phishing-detection model.

To train or update the model, review and run:

```bash
python backend/train_model.py
```

The trained model is stored inside the `backend/models` directory and loaded using Joblib.

---

## 🔐 Security and Privacy

- The default backend runs locally on `127.0.0.1`.
- URLs are analyzed through the locally running Python service.
- Do not enter personal information on websites marked suspicious or dangerous.
- Never use real phishing websites for testing.
- Use safe test domains, controlled lab environments, or authorized security datasets.

---

## ⚠️ Disclaimer

This project was created for educational and cybersecurity-learning purposes. PhishGuard may produce false positives or false negatives. The developer is not responsible for damage, loss, or misuse resulting from reliance on the tool.

Only test websites and systems that you own or have permission to assess.

---

## 🔮 Future Improvements

- Cloud deployment support
- Improved domain-age verification
- Expanded threat-intelligence integration
- Better explainable-AI results
- Firefox and Microsoft Edge support
- Automatic model retraining
- Enhanced admin dashboard
- More phishing datasets
- Reduced false-positive rate

---

## 👨‍💻 Author

**Adarsh Anand**

- GitHub: [@adarsh8901](https://github.com/adarsh8901)
- Project Repository: [PhishGuard](https://github.com/adarsh8901/phishguard)

---

## 🤝 Contributing

Contributions, suggestions and issue reports are welcome.

1. Fork the repository.
2. Create a new branch.
3. Make your changes.
4. Commit your changes.
5. Push the branch.
6. Open a pull request.

---

## ⭐ Support

If you find this project useful, consider giving the repository a star.

---

## 📄 License

This project is currently provided for educational use. Add a dedicated `LICENSE` file before distributing or using it commercially.
