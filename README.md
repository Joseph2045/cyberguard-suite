
 🛡️ CyberGuard Suite

CyberGuard Suite is an all-in-one cybersecurity toolkit designed to help users scan and defend against common digital threats. It integrates powerful tools and an education center to improve user awareness and cyber hygiene.



🚀 Features

 🔍 1. URL Security Scanner
- Detects phishing and malicious URLs using machine learning and heuristics.
- Checks for suspicious patterns and compares against known blacklists.

 📧 2. Email Security Analyzer
- Analyzes email headers and content to detect spoofing or phishing attempts.

 🕵️‍♂️ 3. Fake Login Detector
- Scans login pages to determine authenticity.
- Uses DOM structure, metadata, and SSL certificate checks.

 🔐 4. Encryption Tool
- Offers secure encryption and decryption of text using AES/RSA.

 🎓 5. Security Education Center
- Provides cybersecurity tutorials and articles.
- Includes an interactive quiz to test user understanding.

---

 🧱 Project Structure

```

CyberGuard/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── Procfile                # For deployment on Render
├── routes/                 # Flask routes (auth, detector, etc.)
├── models/                 # Database models
├── static/                 # CSS, JS, assets
├── templates/              # HTML templates
├── config.py               # Configuration (e.g. DB, secret keys)
└── README.md

````

---

 💻 Technologies Used

| Component        | Technology                      |
|------------------|----------------------------------|
| Frontend         | HTML, CSS (Tailwind), JavaScript |
| Backend          | Flask (Python)                  |
| Database         | MySQL                           |
| ML/Detection     | Scikit-learn, Regex, Heuristics |
| Authentication   | Flask-Login                     |
| Deployment       |  Localhost                      |



 ⚙️ Installation & Running Locally

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/cyberguard-suite.git
cd cyberguard-suite

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
python app.py
````

App will be accessible at `http://localhost:5000`


🔐 Security Considerations

* Input sanitization and validation
* HTTPS support when deployed
* Security question-based password reset
* Secure session management (Flask-Login)
* Uses AES encryption for data confidentiality


 👨‍💻 Author

-name:Joseph Marcusy Kibiki
-PHone: 0618780208
       0674837151
-enail:josephkibiki60@gmail.com 


📜 License

MIT License - feel free to use and modify with attribution.

