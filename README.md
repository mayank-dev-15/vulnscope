# vulnscope

[![Live Demo](https://img.shields.io/badge/🚀_Live_Demo-Visit-blue?style=for-the-badge)](https://mayank-dev-15.github.io/vulnscope-demo)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Language](https://img.shields.io/badge/Language-Python/FastAPI/React-green)

Automated Vulnerability Intelligence Platform with real-time CVE monitoring, exploit correlation, and risk scoring.

`security` `cve` `vulnerability` `fastapi` `react`

---

## ✨ Features

- Real-time CVE monitoring via NVD API
- Exploit correlation using CIRCL CVE database
- Risk scoring engine (0-10 scale based on CVSS, exploit availability, age)
- Beautiful React dashboard with charts and stats
- REST API built with FastAPI
- Async data fetching with httpx
- SQLite caching for offline access
- Search and filter CVEs by severity, date, keyword
- Trend analysis and statistics

---

## 🚀 Live Demo

**[View Demo →](https://mayank-dev-15.github.io/vulnscope-demo)**

The demo is hosted on GitHub Pages. No installation needed — just click and explore.

---

## 🛠️ Tech Stack

- Python 3.11+
- FastAPI
- React
- httpx
- aiosqlite
- NVD API
- CIRCL API
- Docker

---

## 📦 Installation

```bash
git clone https://github.com/mayank-dev-15/vulnscope.git
cd vulnscope
```

```bash
cd vulnscope
pip install -r requirements.txt
# Start backend
cd backend && uvicorn app.main:app --reload
# Start frontend
cd frontend && npm install && npm start
# Or use Docker
docker-compose up
```

---

## 💡 Usage

- Visit the dashboard to see latest CVEs
- Search by CVE ID or keyword
- Filter by severity (Critical, High, Medium, Low)
- Click any CVE for full details and risk score
- API available at `/api/docs` (Swagger UI)

---

## 📁 Project Structure

```
vulnscope/
├── README.md          # This file
├── Demo.md            # Demo documentation
├── LICENSE            # MIT License
└── ...                # Source files
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

---

## 📄 License

This project is licensed under the MIT License.

---

## 🔗 Links

- **Live Demo:** [https://mayank-dev-15.github.io/vulnscope-demo](https://mayank-dev-15.github.io/vulnscope-demo)
- **Source Code:** [github.com/mayank-dev-15/vulnscope](https://github.com/mayank-dev-15/vulnscope)
- **Issues:** [github.com/mayank-dev-15/vulnscope/issues](https://github.com/mayank-dev-15/vulnscope/issues)
- **Releases:** [github.com/mayank-dev-15/vulnscope/releases](https://github.com/mayank-dev-15/vulnscope/releases)
- **Demo Docs:** [Demo.md](https://github.com/mayank-dev-15/vulnscope/blob/main/Demo.md)

---

*Built with ❤️ by [Mayank Basena](https://github.com/mayank-dev-15) · 15 · GSoC 2027 Aspirant*

---

## ⚠️ Attribution & Credit Notice

This project is created and maintained by **Mayank Basena** ([@mayank-dev-15](https://github.com/mayank-dev-15)).

If you fork, use, modify, or derive work from this repository, **you must give proper credit** to the original author. This includes:

- Keeping this attribution section intact in any fork or derivative work
- Crediting **Mayank Basena** in your project's README or documentation
- Linking back to the original repository

**Failure to provide proper credit is a violation of the spirit of open source and may result in a DMCA takedown request.**

> *"No AI. No Shortcuts."* — Mayank Basena
