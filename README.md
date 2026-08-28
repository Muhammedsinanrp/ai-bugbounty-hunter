# 🎯 AI-BugBounty-Hunter v1.0

> **AI-Powered Bug Bounty Automation Platform** — One tool, three interfaces: **Telegram Bot**, **Linux CLI**, **Windows CLI**.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Telegram Bot](https://img.shields.io/badge/Telegram-Bot-blue?logo=telegram)](https://t.me/loqclowbot)
[![Multi-User](https://img.shields.io/badge/Multi--User-Supported-green)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Telegram-lightgrey)]()

---

## 🖥️ Three Ways to Use

```
┌─────────────────────────────────────────────────────────┐
│                  AI-BugBounty-Hunter v1.0               │
├─────────────────┬──────────────────┬────────────────────┤
│  Telegram Bot   │   Linux CLI      │   Windows CLI      │
│  (Multi-User)   │   (System-wide)  │   (System-wide)    │
│                 │                  │                    │
│ /scan domain    │ bugbounty domain │ bugbounty domain   │
│ /quick domain   │ bugbounty --quick│ bugbounty --quick  │
│ /report         │ bugbounty --report bugbounty --report │
│ /findings       │ bugbot (bot)     │ bugbot (bot)       │
└─────────────────┴──────────────────┴────────────────────┘
```

---

## ⚡ Quick Install

### Linux / macOS
```bash
git clone https://github.com/Muhammedsinanrp/ai-bugbounty-hunter.git
cd ai-bugbounty-hunter
bash install_linux.sh
```
Now use from anywhere:
```bash
bugbounty example.com
bugbot
```

### Windows
```bat
git clone https://github.com/Muhammedsinanrp/ai-bugbounty-hunter.git
cd ai-bugbounty-hunter
install_windows.bat
```
Now use from anywhere (after restarting terminal):
```bat
bugbounty example.com
bugbot
```

### Python Package (pip install)
```bash
pip install -e .
bugbounty example.com
bugbot
```

---

## 🤖 Telegram Bot — Multi-User

The Telegram bot supports **unlimited simultaneous users**. Each user gets their own:
- Independent scan session
- AI provider & model settings
- API key (never stored to disk)
- Report platform preference

### Setup
1. Get your token from [@BotFather](https://t.me/BotFather) → `/newbot`
2. Configure:
```bash
# Linux
export TELEGRAM_BOT_TOKEN="your-token-here"
bugbot

# Windows
set TELEGRAM_BOT_TOKEN=your-token-here
bugbot

# Or edit bot_config.json:
{ "telegram_token": "your-token" }
```
3. Open your bot → send `/start`

### Bot Commands

| Command | Description |
|---------|-------------|
| `/scan example.com` | 🚀 Full AI pipeline scan |
| `/quick example.com` | ⚡ Passive recon (no active traffic) |
| `/status` | 📊 Your scan progress |
| `/cancel` | 🛑 Cancel your scan |
| `/findings` | 🔎 View your findings |
| `/findings critical` | Filter by severity |
| `/report` | 📄 Get report as file |
| `/myconfig` | ⚙️ Your settings |
| `/mystats` | 📈 Your stats |
| `/setprovider openai` | Switch AI provider |
| `/setmodel gpt-4o` | Set AI model |
| `/setkey sk-xxx` | Set API key (auto-deleted) |
| `/setplatform bugcrowd` | Set report platform |

### Run Bot 24/7 on Linux Server
```bash
# Option 1: Screen session
screen -S bugbot
export TELEGRAM_BOT_TOKEN="your-token"
bugbot
# Ctrl+A, D  ← detach

# Option 2: Systemd service (created by install_linux.sh)
nano .env               # Add TELEGRAM_BOT_TOKEN=your-token
systemctl enable --now bugbounty-bot
systemctl status bugbounty-bot

# Option 3: PM2
pm2 start "bugbot" --name bugbounty-bot
```

---

## 🖥️ CLI Usage (Linux & Windows)

### After Installation
```bash
# Full AI pipeline scan
bugbounty example.com

# Quick passive recon (safe, no active scanning)
bugbounty example.com --quick

# Recon only (subdomains, live hosts, tech stack)
bugbounty example.com --recon-only

# Use OpenAI
bugbounty example.com --ai-provider openai --ai-model gpt-4o

# Use Anthropic Claude
bugbounty example.com --ai-provider anthropic --ai-model claude-3-5-sonnet-20241022

# Use Groq (fast, free tier)
bugbounty example.com --ai-provider groq --ai-model llama-3.1-70b-versatile

# Stealth mode (random delays, slower)
bugbounty example.com --stealth

# Generate HackerOne report
bugbounty example.com --report --platform hackerone

# Generate Bugcrowd report
bugbounty example.com --report --platform bugcrowd

# Restrict scan scope
bugbounty example.com --scope api.example.com app.example.com

# Send results to Slack/Discord
bugbounty example.com --webhook https://hooks.slack.com/...

# Full help
bugbounty --help
```

### Without Installation (direct Python)
```bash
# Linux / macOS
python3 cli.py example.com
python3 telegram_bot.py        # Bot
python3 main.py --bot          # Bot via main

# Windows
python cli.py example.com
python telegram_bot.py
```

---

## 🧠 Pipeline Phases

```
Target Domain
     │
     ▼
Phase 1: RECONNAISSANCE
  ├── CRT.sh Certificate Transparency
  ├── Wayback Machine historical data
  ├── SecurityTrails API (optional key)
  └── AI-predicted subdomains from patterns
     │
     ▼
Phase 2: SURFACE ENUMERATION
  ├── HTTP/HTTPS live host probing
  ├── Technology stack fingerprinting
  └── URL crawling + parameter extraction
     │
     ▼
Phase 3: VULNERABILITY SCANNING
  ├── XSS  (reflected, stored, DOM)
  ├── SQLi (error, time-based, boolean)
  ├── SSTI (Jinja2, Twig, Freemarker...)
  ├── SSRF (cloud metadata endpoints)
  ├── LFI  (path traversal)
  ├── Open Redirect
  ├── IDOR (numeric IDs + path-based)
  ├── API  (CORS, secrets, GraphQL)
  └── Web3 (RPC endpoints)
     │
     ▼
Phase 4: AI ANALYSIS & VALIDATION
  ├── AI enrichment (CVSS, impact, PoC, attack chain)
  ├── 7-Question Validation Gate (false positive filter)
  └── Smart priority scoring
     │
     ▼
Phase 5: REPORT GENERATION
  ├── Individual finding reports
  ├── Executive summary
  └── Combined platform-ready report
```

---

## 🤖 AI Providers

| Provider | Free? | Setup |
|----------|-------|-------|
| **Ollama** (default) | ✅ Free | `curl -fsSL https://ollama.com/install.sh \| sh && ollama pull llama3` |
| **Groq** | ✅ Free tier | Get key at [console.groq.com](https://console.groq.com) |
| **OpenAI** | 💰 Paid | `export AI_API_KEY=sk-your-key` |
| **Anthropic** | 💰 Paid | `export AI_API_KEY=sk-ant-your-key` |

---

## 📁 Project Structure

```
ai-bugbounty-hunter/
├── main.py              ← Unified entry point (CLI + Bot)
├── cli.py               ← Full CLI interface
├── telegram_bot.py      ← Multi-user Telegram bot
├── core/                ← Agent, Config, Database, Logger
├── recon/               ← Subdomain, Crawler, Port, Tech, OSINT
├── scanners/            ← XSS, SQLi, SSTI, SSRF, LFI, IDOR, API, Web3
├── ai_engine/           ← LLM Client, Analyzer, Validator, Payload, Report
├── utils/               ← HTTP Client, Wordlists, Proxies, Rate Limiter
├── install_linux.sh     ← Linux system installer (creates bugbounty + bugbot)
├── install_windows.bat  ← Windows installer
├── run_bot.sh           ← Quick bot launcher (Linux)
├── run_bot.bat          ← Quick bot launcher (Windows)
├── config.json          ← Default configuration
├── bot_config.json      ← Bot token (gitignored)
├── requirements.txt     ← Python dependencies
└── pyproject.toml       ← Package config (pip install -e .)
```

---

## 🔧 Configuration (`config.json`)

```json
{
  "ai": {
    "provider": "ollama",
    "model": "llama3",
    "api_key": ""
  },
  "target": {
    "rate_limit": 10,
    "max_pages": 500,
    "concurrent_requests": 20
  },
  "scanners": {
    "xss": {"enabled": true},
    "sqli": {"enabled": true},
    "ssti": {"enabled": true},
    "ssrf": {"enabled": true},
    "lfi":  {"enabled": true}
  },
  "reports": {
    "platform": "hackerone"
  }
}
```

---

## 🌍 Environment Variables

| Variable | Description |
|----------|-------------|
| `TELEGRAM_BOT_TOKEN` | Your Telegram bot token |
| `TELEGRAM_ALLOWED_USERS` | Comma-separated user IDs (restrict access) |
| `AI_API_KEY` | API key for OpenAI / Anthropic / Groq |
| `PYTHONUTF8` | Set to `1` (auto-set on Windows) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key (optional) |

---

## ⚠️ Legal & Ethical Use

> **Only scan targets you have explicit written permission to test.**
> Unauthorized scanning is illegal under CFAA, Computer Misuse Act, and similar laws worldwide.
> This tool is for authorized security testing and bug bounty programs only.

---

*Built for the bug bounty community. Use responsibly. ⭐ Star if useful!*
