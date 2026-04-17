# 🛡️ SecureEye — Cybersecurity Advisory Portal

A full-stack threat intelligence platform for the Wipro SecureEye team.
Built with **FastAPI + React + Tailwind CSS**.

---

## ✅ Features

| Module | Description |
|---|---|
| 🔐 Auth & RBAC | JWT login, roles: Admin / Analyst / Viewer |
| 📋 Advisory Management | Create, edit, approve, publish, reject advisories |
| 🏭 Sector Categorization | BFSI, Healthcare, Hi-Tech, Government, Energy, Retail |
| 🤖 Threat Feed Engine | CISA KEV + NVD CVE API + RSS blogs, every 30 min |
| 🚨 Critical Alerts | Auto-detect CVSS ≥8.5 or KEV → email + Slack + Teams |
| 🔍 Smart Search | Full-text across advisories, plus live web search with optional Google override |
| 📊 Analytics Dashboard | Live stats, severity chart, sector distribution, trending CVEs |
| ☢️ Zero-Day Tracker | Track unpatched zero-days with status (Exploited/Patched/Mitigated) |
| 🕵️ IOC Management | Track IPs, domains, file hashes, URLs per advisory |
| 📅 Threat Timeline | Chronological published advisory feed |
| 💬 Analyst Annotations | Internal notes per advisory |
| 👥 User Management | Create, edit, disable users (Admin only) |
| 📡 Feed Logs | History of all automated feed runs |

---

## 🚀 Option A — Run Locally (Recommended for Development)

### Prerequisites
- Python 3.10+ — https://python.org/downloads
- Node.js 18+ — https://nodejs.org
- Git (optional)

---

### Step 1 — Clone / Extract the project
```bash
# If using git:
git clone <your-repo> secureeye
cd secureeye

# Or just extract the ZIP and cd into it
cd cybersecurity-portal
```

---

### Step 2 — Set up the Backend

```bash
cd backend

# Create a virtual environment
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment variables
cp .env.example .env
# Open .env and set your SECRET_KEY (required), and optionally SMTP/Slack settings
```

Edit `.env` — at minimum change `SECRET_KEY`:
```
SECRET_KEY=your-super-secret-random-string-here-make-it-long
```

---

### Step 3 — Start the Backend

```bash
# From the /backend directory, with venv activated:
python main.py
```

You should see:
```
INFO:     Uvicorn running on http://0.0.0.0:8000
INFO:     Database seeded successfully
INFO:     Feed scheduler started — polling every 30 minutes
```

**Backend is live at:** http://localhost:8000  
**API docs (Swagger):** http://localhost:8000/docs  
**Health check:** http://localhost:8000/api/health

---

### Step 4 — Set up the Frontend

Open a **new terminal window**:

```bash
cd frontend

# Install Node dependencies
npm install

# Start the dev server
npm run dev
```

You should see:
```
  VITE v5.x.x  ready in XXX ms
  ➜  Local:   http://localhost:5173/
```

**Frontend is live at:** http://localhost:5173

---

### Step 5 — Login

Open http://localhost:5173 in your browser.

| Role | Username | Password |
|---|---|---|
| Admin | `admin` | `Admin@12345` |
| Analyst | `analyst` | `Analyst@12345` |
| Viewer | `viewer` | `Viewer@12345` |

---

## 🐳 Option B — Docker (One Command)

### Prerequisites
- Docker Desktop — https://www.docker.com/products/docker-desktop

```bash
cd cybersecurity-portal

# Copy env file
cp backend/.env.example backend/.env

# Start everything
docker compose up --build
```

- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- Swagger docs: http://localhost:8000/docs

---

## ⚙️ Configuration Reference (.env)

| Variable | Description | Required |
|---|---|---|
| `SECRET_KEY` | JWT signing key — change this! | ✅ Yes |
| `DATABASE_URL` | SQLite (default) or PostgreSQL | Optional |
| `SMTP_HOST` | Gmail/SMTP server for email alerts | Optional |
| `SMTP_USER` | Your email address | Optional |
| `SMTP_PASSWORD` | Gmail App Password (not account password) | Optional |
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for alerts | Optional |
| `TEAMS_WEBHOOK_URL` | MS Teams connector webhook | Optional |
| `FEED_POLL_INTERVAL_MINUTES` | How often to fetch CISA/NVD (default: 30) | Optional |
| `CRITICAL_CVSS_THRESHOLD` | CVSS score to auto-flag critical (default: 8.5) | Optional |
| `WEB_SEARCH_PROVIDER` | `brave`, `google`, or `threat_intel` | Optional |
| `WEB_SEARCH_RESULTS_LIMIT` | Max external web results per search (default: 10) | Optional |
| `GOOGLE_SEARCH_API_KEY` | Google Custom Search JSON API key | Optional |
| `GOOGLE_SEARCH_ENGINE_ID` | Google Programmable Search Engine ID (`cx`) | Optional |

### Default Web Search
By default, Smart Search uses Brave-powered web results without requiring an API key.

```env
WEB_SEARCH_PROVIDER=brave
WEB_SEARCH_RESULTS_LIMIT=10
```

### Enable Google Web Search
1. Create a Google Programmable Search Engine
2. Configure it to search the web
3. Generate a Custom Search JSON API key
4. Add these values to `backend/.env`:

```env
WEB_SEARCH_PROVIDER=google
WEB_SEARCH_RESULTS_LIMIT=10
GOOGLE_SEARCH_API_KEY=your-google-api-key
GOOGLE_SEARCH_ENGINE_ID=your-programmable-search-engine-id
```

If web search is temporarily unavailable, Smart Search falls back to the built-in threat intelligence search sources.

### Setting up Gmail SMTP
1. Enable 2FA on your Google account
2. Go to myaccount.google.com → Security → App Passwords
3. Create an app password for "Mail"
4. Use it as `SMTP_PASSWORD` in `.env`

### Setting up Slack Webhook
1. Go to https://api.slack.com/apps
2. Create app → Incoming Webhooks → Add New Webhook
3. Paste the URL as `SLACK_WEBHOOK_URL`

---

## 📁 Project Structure

```
cybersecurity-portal/
├── backend/
│   ├── main.py              # FastAPI app, startup, scheduler
│   ├── config.py            # Settings from .env
│   ├── database.py          # SQLAlchemy engine
│   ├── models.py            # All DB models
│   ├── schemas.py           # Pydantic request/response schemas
│   ├── auth.py              # JWT + password hashing
│   ├── requirements.txt
│   ├── .env.example
│   ├── routes/
│   │   ├── auth.py          # Login, refresh, /me
│   │   ├── advisories.py    # Full advisory CRUD + publish/reject
│   │   ├── dashboard.py     # Analytics & stats
│   │   ├── admin.py         # Users, sectors, IOCs, feeds
│   │   └── collaboration.py # Annotations & analyst tasks
│   └── services/
│       ├── threat_feeds.py  # CISA KEV + NVD + RSS ingestion
│       └── alert_service.py # Email + Slack + Teams alerts
│
└── frontend/
    ├── src/
    │   ├── App.jsx           # Router + auth guards
    │   ├── main.jsx          # Entry point
    │   ├── index.css         # Tailwind + global styles
    │   ├── context/
    │   │   └── AuthContext.jsx
    │   ├── services/
    │   │   └── api.js        # Axios + auto token refresh
    │   ├── utils/
    │   │   └── helpers.js    # Colors, formatters
    │   ├── components/
    │   │   ├── Layout.jsx
    │   │   ├── Sidebar.jsx
    │   │   ├── AdvisoryCard.jsx
    │   │   └── SeverityBadge.jsx
    │   └── pages/
    │       ├── Login.jsx
    │       ├── Dashboard.jsx
    │       ├── Advisories.jsx
    │       ├── AdvisoryDetail.jsx
    │       ├── AdvisoryForm.jsx
    │       ├── SmartSearch.jsx
    │       ├── ThreatTimeline.jsx
    │       ├── ZeroDayTracker.jsx
    │       ├── IOCManagement.jsx
    │       ├── AlertLogs.jsx
    │       ├── UserManagement.jsx
    │       ├── ManageSectors.jsx
    │       └── FeedLogs.jsx
    ├── package.json
    ├── vite.config.js
    ├── tailwind.config.js
    └── Dockerfile
```

---

## 🔌 REST API Reference

| Method | Endpoint | Description | Auth |
|---|---|---|---|
| POST | `/api/auth/login` | Login → tokens | Public |
| GET | `/api/auth/me` | Current user | Any |
| GET | `/api/advisories` | List with filters | Any |
| POST | `/api/advisories` | Create advisory | Analyst+ |
| GET | `/api/advisories/{id}` | Get detail | Any |
| PUT | `/api/advisories/{id}` | Update | Analyst+ |
| POST | `/api/advisories/{id}/publish` | Publish + alert | Analyst+ |
| POST | `/api/advisories/{id}/reject` | Reject | Admin |
| GET | `/api/advisories/search?q=CVE` | Smart search | Any |
| GET | `/api/dashboard/stats` | Dashboard analytics | Any |
| GET | `/api/admin/users` | List users | Admin |
| POST | `/api/admin/users` | Create user | Admin |
| GET | `/api/admin/sectors` | List sectors | Any |
| POST | `/api/admin/feeds/run` | Trigger feed | Analyst+ |
| GET | `/api/admin/iocs` | List IOCs | Any |
| POST | `/api/admin/iocs` | Add IOC | Analyst+ |

Full interactive Swagger docs at: http://localhost:8000/docs

---

## 🛠 Troubleshooting

**`ModuleNotFoundError`** → Make sure venv is activated: `source venv/bin/activate`

**Port 8000 already in use** → `kill $(lsof -t -i:8000)` or change port in `main.py`

**Port 5173 already in use** → Change in `vite.config.js`

**Feed not running** → Check the console for APScheduler logs; or manually click "Run Feeds Now" on Dashboard

**Email alerts not sending** → Ensure `SMTP_USER` and `SMTP_PASSWORD` are set in `.env`; use Gmail App Password

**CORS error in browser** → Ensure backend is running on port 8000 and frontend on 5173

---

## 📋 Default Sectors (Pre-loaded)

- BFSI (Banking, Financial Services & Insurance)
- Healthcare
- Hi-Tech (IT, Cloud, Software)
- Entertainment
- Government
- Energy
- Retail

Add more in **Admin → Manage Sectors**.
