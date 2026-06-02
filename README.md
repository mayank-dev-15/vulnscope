# VulnScope 🔍

**Automated Vulnerability Intelligence Platform**

A real-time vulnerability monitoring and correlation engine that aggregates CVE data from multiple sources, enriches it with exploit availability, and delivers actionable intelligence via a beautiful web dashboard.

## Features

- **Real-time CVE Aggregation** — Pulls from NVD, GitHub Advisory Database, and OSV
- **Exploit Correlation** — Cross-references with Exploit-DB, Metasploit modules, and PoC repositories
- **Risk Scoring** — Custom CVSS-based scoring with environmental factors
- **Alert System** — Slack, Discord, Telegram notifications for critical vulns
- **REST API** — Full OpenAPI 3.0 documented API
- **Beautiful Dashboard** — Real-time charts, trend analysis, and drill-down views

## Tech Stack

- **Backend:** Python 3.11+, FastAPI, SQLAlchemy, Celery
- **Frontend:** React 18, TypeScript, TailwindCSS, Recharts
- **Database:** PostgreSQL, Redis
- **Deployment:** Docker Compose, GitHub Actions CI/CD

## Quick Start

```bash
git clone https://github.com/mayank-dev-15/vulnscope.git
cd vulnscope
docker compose up --build
# Open http://localhost:3000
```

## API

```
GET /api/v1/cves?severity=critical&limit=10
GET /api/v1/cves/{cve_id}
GET /api/v1/stats/trends?days=30
POST /api/v1/alerts/configure
```

## Screenshots

![Dashboard](docs/screenshots/dashboard.png)
![CVE Detail](docs/screenshots/cve-detail.png)
![API Docs](docs/screenshots/api-docs.png)

## License

MIT License — see [LICENSE](LICENSE)
