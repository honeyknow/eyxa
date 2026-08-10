<div align="center">
  <h1>🦅 EYXA EDR: AI-POWERED THREAT HUNTING</h1>
  <p><strong>A tactical Endpoint Detection and Response platform engineered for zero-trust environments.</strong></p>
  <p>
    <a href="https://github.com/honeyknow/eyxa/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
    <img src="https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white" alt="Windows">
    <img src="https://img.shields.io/badge/c-%2300599C.svg?style=flat&logo=c&logoColor=white" alt="C">
    <img src="https://img.shields.io/badge/python-3670A0?style=flat&logo=python&logoColor=ffdd54" alt="Python">
    <img src="https://img.shields.io/badge/FastAPI-009485?style=flat&logo=fastapi&logoColor=white" alt="FastAPI">
    <img src="https://img.shields.io/badge/react-%2320232a.svg?style=flat&logo=react&logoColor=%2361DAFB" alt="React">
    <img src="https://img.shields.io/badge/sqlite-%2307405e.svg?style=flat&logo=sqlite&logoColor=white" alt="SQLite">
    <img src="https://img.shields.io/badge/docker-%230db7ed.svg?style=flat&logo=docker&logoColor=white" alt="Docker">
    <img src="https://img.shields.io/badge/Engine-Sigma-black?style=flat" alt="Sigma">
  </p>
</div>

---

## 📖 Overview

Eyxa is a comprehensive, full-stack Endpoint Detection and Response (EDR) platform designed for Windows environments. It leverages native Windows APIs and ETW (Event Tracing for Windows) to provide deep system visibility, combined with a blazing-fast Python/FastAPI backend and an intuitive React-based dashboard for real-time threat hunting, alerts, and incident response.

## ✨ Key Features

- **Lightweight Windows Agent:** A native C-based agent that taps directly into Sysmon, AMSI (Antimalware Scan Interface), and DNS ETW channels with minimal system overhead.
- **Real-Time Telemetry:** Continuous streams of process creations, network connections, and file modifications pushed instantly to the backend.
- **Sigma Rule Engine:** Native integration with [Sigma](https://github.com/SigmaHQ/sigma) for writing and evaluating powerful threat detection rules against live telemetry.
- **Live Response Capabilities:** Establish persistent WebSocket connections to endpoints to execute immediate response actions (e.g., kill processes, run commands).
- **AI Assistant Analysis:** Built-in LLM integrations (powered by Groq) to instantly summarize alerts and calculate the "blast radius" of compromised processes.
- **Effortless Deployment:** Completely dockerized infrastructure with automated Cloudflare tunnel provisioning.

---

## 🏗️ Architecture

The Eyxa platform is composed of four primary components:

1. **[Agent (`/agent`)](./agent/AGENT_README.MD):** The core C executable (`eyxa.exe`) running as a Windows Service (Session 0). Captures system events, normalizes them, and ships them securely to the backend.
2. **[Backend (`/backend`)](./backend/BACKEND_README.MD):** A FastAPI server running on Python 3.11+. Handles API ingestion, Sigma rule evaluation (via pySigma and SQLite), and WebSocket C2 channels.
3. **[Dashboard (`/dashboard`)](./dashboard/DASHBOARD_README.MD):** A sleek React Single-Page Application (SPA) built with Vite. Provides the analyst interface.
4. **[Installer (`/installer`)](./installer/INSTALLER_README.MD):** Automated batch and PowerShell scripts to seamlessly deploy the agent and configure Microsoft Sysmon on target machines.

---

## 🚀 Getting Started

Eyxa is designed to be easily deployable using Docker.

### Prerequisites
- Docker and Docker Compose
- Windows target machines (for the Agent)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/honeyknow/eyxa.git
   cd eyxa
   ```

2. **Launch the platform:**
   Use the provided start script to build and launch the Docker containers, and automatically provision a secure Cloudflare tunnel.
   ```bash
   ./start.sh
   ```

3. **Access the Dashboard:**
   Once the script finishes, it will print a dynamic Cloudflare URL (e.g., `https://random-words.trycloudflare.com`). Navigate to this URL in your browser.

4. **Deploy the Agent:**
   Inside the dashboard, click **"Add Endpoint"** to view the PowerShell installation command. Run this command as an Administrator on your target Windows machines.

---

## 📂 Repository Structure

```text
eyxa/
├── agent/                 # C source code for the Windows EDR Agent
│   ├── config/            # Agent configurations (eyxa.xml, sysmon_config.xml)
│   ├── src/               # Core C agent modules (main.c, sysmon_reader.c, etc.)
│   ├── AGENT_README.MD    # Agent documentation
│   └── Makefile           # Build system for the agent
├── backend/               # FastAPI server, Database schemas, and API routes
│   ├── api/               # FastAPI endpoints (ingest, rules, dashboard, AI)
│   ├── db/                # SQLite database and schema (schema.sql)
│   ├── detection/         # Threat hunting engine and Sigma rules
│   ├── static/            # Compiled React dashboard assets
│   ├── BACKEND_README.MD  # Backend documentation
│   ├── main.py            # FastAPI entry point
│   └── requirements.txt   # Python dependencies
├── dashboard/             # React frontend UI
│   ├── public/            # Static assets and agent installer downloads
│   ├── src/               # React components, contexts, and hooks
│   ├── DASHBOARD_README.MD# Dashboard documentation
│   ├── index.html         # Application entry HTML
│   └── package.json       # Node dependencies
├── installer/             # Deployment scripts
│   ├── eyxa.exe           # Pre-compiled agent binary
│   ├── terminator.exe     # System tray UI
│   ├── install.ps1        # Agent deployment script
│   ├── uninstall.ps1      # Agent removal script
│   └── INSTALLER_README.MD# Installer documentation
├── docker-commands.txt    # Helpful Docker/DB cheat sheet
├── docker-compose.yml     # Container orchestration
├── Dockerfile             # Multi-stage build for Backend & Dashboard
├── ROOT_STRAY_FILES_README.MD # Root configuration docs
└── start.sh               # Quick-start script for Docker + Cloudflare
```

*For more information on the root deployment files, see the [Root Files Documentation](./ROOT_STRAY_FILES_README.MD).*

---

## 🛠️ Troubleshooting & Commands

For AI Assistant troubleshooting, database interaction, or container management, please refer to the `docker-commands.txt` file included in the root directory. It contains a curated list of useful administrative commands.

---

## 🔒 Security Notice

Please note that this EDR is designed for educational and internal deployment purposes. Certain configurations (such as `SkipTlsVerify` in the installer) are optimized for demo environments and should be secured before production use. See the specific component documentation for known vulnerabilities and architectural decisions.

---

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
