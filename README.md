# 🛡️ Automated IP Threat Intelligence & Incident Response Tool

> A real-time IP threat analysis platform that aggregates intelligence from AbuseIPDB and Shodan to deliver instant risk assessments, abuse reports, and attack surface visibility.

---

## 📖 What It Does

Users enter any public IP address into the web dashboard, and the tool queries **AbuseIPDB** and **Shodan** in real time to build a comprehensive threat profile. The system returns:

- **Abuse Confidence Score** — how likely the IP is involved in malicious activity (0–100%)
- **Total Abuse Reports** — number of times the IP has been reported
- **Open Ports** — live detection of exposed services (HTTP, SSH, DNS, RDP, etc.)
- **Country & ISP** — geolocation and network provider identification
- **Risk Level Classification** — automated scoring engine that categorizes each IP as **CRITICAL**, **HIGH**, **MEDIUM**, or **LOW** based on abuse confidence thresholds

All results are persisted to a local SQLite database, enabling full search history tracking and audit logging of previously analyzed targets.

---

## 🧰 Tech Stack

| Layer       | Technology                          |
|-------------|-------------------------------------|
| Backend     | Python, Flask                       |
| Database    | SQLAlchemy ORM, SQLite              |
| APIs        | AbuseIPDB API, Shodan API           |
| Frontend    | HTML, CSS, Jinja2 Templates         |
| Testing     | unittest, unittest.mock             |

---

## ⚡ Features

- **Real-time IP reputation lookup** — instant abuse scoring and report counts from AbuseIPDB
- **Live open port detection** — exposed service enumeration via Shodan with clickable port inspection panels
- **Risk level scoring engine** — automated CRITICAL / HIGH / MEDIUM / LOW classification based on abuse confidence
- **Search history tracking** — all analyzed IPs are logged with timestamps and risk levels for audit review
- **War room style dashboard UI** — threat report pages with a dark, aggressive cybersecurity aesthetic
- **JSON API endpoint** — programmatic access to threat data via `/api/analyze/<ip>`
- **IP validation** — input sanitization and format validation on all routes
- **Clear history** — one-click purge of all search logs from the database

---

## 🚀 Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/automated-ir-tool.git
cd automated-ir-tool
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Create environment file

Create a `.env` file in the project root with your API keys:

```env
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
SHODAN_API_KEY=your_shodan_api_key_here
SECRET_KEY=your_secret_key_here
```

> **Note:** You can obtain a free API key from [AbuseIPDB](https://www.abuseipdb.com/account/api) and [Shodan](https://account.shodan.io/).

### 4. Run the application

```bash
python app.py
```

The server will start on `http://localhost:5000`. Open it in your browser to begin analyzing IP addresses.

---

## 🔌 APIs Used

| API | Purpose | Link |
|-----|---------|------|
| **AbuseIPDB** | IP reputation scoring, abuse confidence metrics, and report aggregation | [abuseipdb.com](https://www.abuseipdb.com/) |
| **Shodan** | Internet-wide host scanning, open port detection, and vulnerability indexing | [shodan.io](https://www.shodan.io/) |

---

## ⚠️ Disclaimer

**This tool is for educational and research purposes only.** The developers assume no liability for misuse. Always ensure you have proper authorization before scanning or analyzing IP addresses that you do not own.
