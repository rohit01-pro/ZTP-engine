# 🛡️Zero Trust Enabled Intelligent IDS Using Machine Learning


<img width="2560" height="1517" alt="Screenshot 2026-01-21 at 8 54 44 PM" src="https://github.com/user-attachments/assets/eb9a22a5-67e7-4d54-9356-dde1a7842196" />
<img width="1543" height="1189" alt="Screenshot 2026-01-21 at 8 55 28 PM" src="https://github.com/user-attachments/assets/828893b4-b923-491a-b12e-6d29a787f350" />
<img width="1476" height="1238" alt="Screenshot 2026-01-21 at 8 56 08 PM" src="https://github.com/user-attachments/assets/33a4fe4e-1721-4826-837d-227f2389f6a3" />


![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)
![XGBoost](https://img.shields.io/badge/XGBoost-EB6B02?style=for-the-badge&logo=xgboost&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)

## 🚀 Project Overview
This project is an advanced **Zero Trust Policy Engine (ZTP Engine)** that functions as an intelligent **Intrusion Detection System (IDS)**.It implements the core principle of Zero Trust: **"Never Trust, Always Verify"**. 

The system continuously verifies user identity, monitors device health in real-time, and applies context-aware policies using Machine Learning to allow or deny access.

---

## ✨ Key Features
* **Continuous Verification:** Identity is verified for every access request, not just at login.
* **Real-time Device Health:** Evaluates OS patches, antivirus status, firewall, and encryption before granting access.
* **ML-Driven Risk Scoring:** Uses **XGBoost** to predict access decisions with high accuracy (target ~95%).
* **Behavioral Anomaly Detection:** Utilizes **Isolation Forest** to detect unusual access patterns that deviate from a user's baseline.
* **Enterprise Architecture:** Dual-database setup using **PostgreSQL** for relational data (users/devices) and **MongoDB** for structured audit logs.

---

## 🛠️ Technology Stack
| Component | Technology | Role |
| :--- | :--- | :--- |
| **Backend** | Python 3.9+, FastAPI | REST API & Core Logic  |
| **ML Engine** | XGBoost & Scikit-learn | Risk Scoring & Decision Making  |
| **Relational DB** | PostgreSQL |User & Device state persistence  |
| **Log DB** | MongoDB | ]High-speed audit trails & Behavioral data |
| **Auth** | JWT & Bcrypt | Secure tokens & Password hashing  |

---

## 🧠 Decision Logic & Mathematical Model
The system calculates a **Total Risk Score** based on a weighted formula:

$$Total \ Risk = (User \ Risk \times 0.40) + (Device \ Risk \times 0.35) + (Context \ Risk \times 0.25)$$

### Risk Thresholds:
* **Score < 50:** **ALLOW** (Access Granted).
* **Score 50 - 80:** **CHALLENGE** (Requires MFA).
* **Score > 80:** **DENY** (Access Blocked).

---

## 📁 Project Structure
```text
ztp-engine/
├── src/
[cite_start]│   ├── api/          # main.py (FastAPI endpoints) [cite: 37, 84]
[cite_start]│   ├── config/       # settings.py (Configuration) [cite: 37]
[cite_start]│   ├── models/       # database.py, schemas.py [cite: 37]
[cite_start]│   ├── services/     # identity, device_health, ml_service [cite: 37, 84]
[cite_start]│   └── utils/        # logger.py, exceptions.py [cite: 37, 84]
[cite_start]├── ml_models/        # Saved XGBoost & Isolation Forest models [cite: 37]
[cite_start]├── logs/             # Structured audit logs [cite: 37]
└── requirements.txt  # Project dependencies
```

## 🏗️ Architecture Flow
1. **Request:** User resource access ke liye request karta hai.
2. **Analysis:** System teen layers par check karta hai: Identity, Device Health, aur Context.
3. **ML Processing:** XGBoost risk score calculate karta hai aur Isolation Forest anomaly detect karta hai.
4. **Decision:** Score ke basis par access Allow, Challenge (MFA), ya Deny hota hai.

## 🔍 API Documentation
Local server start karne ke baad, aap interactive documentation yahan dekh sakte hain:
👉 [http://localhost:8000/docs](http://localhost:8000/docs)

### Primary Endpoints:
* `POST /auth/register` - Naya user register karne ke liye.
* `POST /devices/register` - Device enroll aur health check ke liye.
* `POST /access/verify` - **Core Logic:** Access grant/deny karne ke liye risk scoring run karta hai.


## ⚙️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/your-username/ztp-engine.git](https://github.com/your-username/ztp-engine.git)
   cd ztp-engine
   ```

```bash
   python -m venv venv
   source venv/bin/activate
```
```bash
   pip install fastapi uvicorn pydantic-settings sqlalchemy psycopg2-binary pymongo motor xgboost scikit-learn passlib[bcrypt] python-jose[cryptography]
```
```bash
   python -m uvicorn src.api.main:app --reload
   ```

<img width="1543" height="1189" alt="Screenshot 2026-01-21 at 8 55 28 PM" src="https://github.com/user-attachments/assets/828893b4-b923-491a-b12e-6d29a787f350" />
<img width="1476" height="1238" alt="Screenshot 2026-01-21 at 8 56 08 PM" src="https://github.com/user-attachments/assets/33a4fe4e-1721-4826-837d-227f2389f6a3" />


## 🛡️ Security & Compliance
This engine is designed to align with NIST SP 800-207 standards. While it does not prevent zero-day vulnerabilities (as no system can), it significantly reduces the blast radius of a breach by isolating compromised devices and identities within minutes

## 👨‍💻 Author
Rohit Kumar

B.Tech Student, Galgotias University
Cybersecurity & Machine Learning Enthusiast
