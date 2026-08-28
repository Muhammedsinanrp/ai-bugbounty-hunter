# 🎯 AI-BugBounty-Hunter v1.0

> **AI-Powered Bug Bounty Automation Platform** — Orchestrates reconnaissance, intelligent vulnerability detection, smart validation, and automated report generation.

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![AI Powered](https://img.shields.io/badge/AI-OpenAI%20%7C%20Anthropic%20%7C%20Groq%20%7C%20Ollama-purple.svg)]()

---

## 🚀 Features

| Feature | Description |
|---------|-------------|
| 🤖 **AI Orchestration** | LLM-powered decision engine (OpenAI / Anthropic / Groq / Ollama) |
| 🔍 **Multi-Source Recon** | CRT.sh, Wayback Machine, SecurityTrails, AI-predicted subdomains |
| 📡 **Smart URL Crawling** | AI-prioritized crawling with GET/POST parameter extraction |
| 🛡️ **Multi-Vector Scanning** | XSS, SQLi, SSTI, SSRF, LFI, IDOR, Open Redirect, API, Web3 |
| 🧠 **AI Validation Gate** | 7-question triage filter — eliminates false positives |
| 🎯 **AI Payload Generation** | Context-aware, WAF-bypassing payloads generated on-the-fly |
| 📝 **Auto Report Generation** | Submission-ready reports for HackerOne, Bugcrowd, Intigriti, Immunefi |
| 🔒 **Stealth Mode** | Rate limiting, proxy rotation, random delays, UA rotation |
| ⚡ **Fully Modular** | Run full pipeline or individual phases independently |
| 🆓 **Free to Use** | Works with Ollama (local, offline) — no paid API required |

---

## 📁 Project Structure

```
ai-bugbounty-hunter/
├── core/
│   ├── agent.py           # AI orchestration engine (5-phase pipeline)
│   ├── config.py          # Configuration management
│   ├── database.py        # SQLite findings database
│   └── logger.py          # Rich terminal logging
├── recon/
│   ├── subdomain.py       # AI-powered subdomain discovery
│   ├── url_crawler.py     # Intelligent URL + parameter crawler
│   ├── port_scanner.py    # HTTP/HTTPS live host detection
│   ├── tech_detect.py     # Technology stack fingerprinting
│   └── osint.py           # OSINT enrichment (DNS, WHOIS, IP)
├── scanners/
│   ├── xss_scanner.py     # XSS detection (reflected, stored, DOM)
│   ├── sqli_scanner.py    # SQL injection (error, time, boolean)
│   ├── ssti_scanner.py    # Template injection (Jinja2, Twig, etc.)
│   ├── ssrf_scanner.py    # SSRF with metadata endpoint probes
│   ├── lfi_scanner.py     # LFI/RFI path traversal
│   ├── open_redirect.py   # Open redirect detection
│   ├── idor_scanner.py    # IDOR / access control testing
│   ├── api_tester.py      # API security (CORS, secrets, GraphQL)
│   └── web3_scanner.py    # Web3 / RPC endpoint detection
├── ai_engine/
│   ├── llm_client.py      # Universal LLM client (multi-provider)
│   ├── analyzer.py        # AI finding enrichment (CVSS, PoC, impact)
│   ├── validator.py       # 7-question false positive elimination gate
│   ├── prioritizer.py     # Smart finding prioritization
│   ├── payload_gen.py     # AI-powered payload + WAF bypass generation
│   └── report_gen.py      # Automated platform-specific report writing
├── utils/
│   ├── http_client.py     # Advanced HTTP client with retry + proxy
│   ├── wordlists.py       # Dynamic wordlist management
│   ├── proxies.py         # Proxy pool rotation and health checking
│   └── ratelimit.py       # Token bucket rate limiter + stealth
├── reports/
│   ├── templates/         # Report templates
│   └── output/            # Generated reports (per-target directories)
├── findings_db/           # SQLite database (auto-created)
├── cli.py                 # Command-line interface
├── config.json            # Default configuration
├── requirements.txt
├── setup.sh               # Linux/macOS one-click setup
└── setup.bat              # Windows one-click setup
```

---

## ⚡ Quick Start

### 1. Setup (Windows)
```bat
setup.bat
```

### 1. Setup (Linux/macOS)
```bash
bash setup.sh
```

### 2. Configure AI Provider

**Option A — Free local AI with Ollama:**
```bash
# Install Ollama: https://ollama.com
ollama pull llama3
# Config already set to Ollama by default
```

**Option B — OpenAI:**
```bash
set AI_API_KEY=sk-your-key-here        # Windows
export AI_API_KEY=sk-your-key-here     # Linux/macOS
```

**Option C — Anthropic Claude:**
```bash
set AI_API_KEY=sk-ant-your-key-here
python cli.py target.com --ai-provider anthropic --ai-model claude-3-5-sonnet-20241022
```

**Option D — Groq (fast, cheap):**
```bash
set AI_API_KEY=gsk_your-groq-key
python cli.py target.com --ai-provider groq --ai-model llama-3.1-70b-versatile
```

---

## 🎮 Usage Examples

```bash
# ── Full Pipeline ─────────────────────────────────────────────────
python cli.py target.com

# ── Full pipeline with OpenAI ─────────────────────────────────────
python cli.py target.com --ai-provider openai --ai-model gpt-4o

# ── Quick passive recon (no active scanning traffic) ──────────────
python cli.py target.com --quick

# ── Recon only — save results for manual review ───────────────────
python cli.py target.com --recon-only

# ── Stealth mode (slower, harder to detect) ───────────────────────
python cli.py target.com --stealth

# ── Generate HackerOne-formatted report from DB ───────────────────
python cli.py target.com --report --platform hackerone

# ── Generate Bugcrowd report ──────────────────────────────────────
python cli.py target.com --report --platform bugcrowd

# ── Validate existing findings without re-scanning ────────────────
python cli.py target.com --validate

# ── Specific scope ────────────────────────────────────────────────
python cli.py target.com --scope api.target.com app.target.com

# ── Exclude patterns ──────────────────────────────────────────────
python cli.py target.com --exclude logout signout

# ── Send results to Slack/Discord ─────────────────────────────────
python cli.py target.com --webhook https://hooks.slack.com/...

# ── Maximum verbosity ─────────────────────────────────────────────
python cli.py target.com -vvv
```

---

## 🔧 Configuration

Edit `config.json` to customize all settings:

```json
{
  "ai": {
    "provider": "ollama",          // openai | anthropic | groq | ollama
    "model": "llama3",
    "api_key": "",                 // Or set AI_API_KEY env var
    "temperature": 0.1
  },
  "target": {
    "rate_limit": 10,              // Requests per second
    "max_pages": 500,
    "concurrent_requests": 20
  },
  "scanners": {
    "xss": {"enabled": true},
    "sqli": {"enabled": true},
    ...
  },
  "reports": {
    "platform": "hackerone"        // hackerone | bugcrowd | intigriti | immunefi
  }
}
```

---

## 🧠 Pipeline Phases

```
Target Domain
     │
     ▼
Phase 1: RECONNAISSANCE
  ├── CRT.sh passive subdomain enum
  ├── Wayback Machine historical data
  ├── SecurityTrails API (optional)
  └── AI-predicted subdomains from patterns
     │
     ▼
Phase 2: SURFACE ENUMERATION
  ├── HTTP/HTTPS live host probing
  ├── Technology stack fingerprinting
  └── AI-guided URL crawling + parameter extraction
     │
     ▼
Phase 3: VULNERABILITY SCANNING
  ├── XSS (reflected, stored, DOM)
  ├── SQL Injection (error, time, boolean)
  ├── SSTI (Jinja2, Twig, Freemarker...)
  ├── SSRF (cloud metadata endpoints)
  ├── LFI/RFI (path traversal)
  ├── Open Redirect
  ├── IDOR (numeric IDs, path-based)
  ├── API Security (CORS, secrets, GraphQL)
  └── Web3 (RPC endpoints, smart contracts)
     │
     ▼
Phase 4: AI ANALYSIS & VALIDATION
  ├── AI enrichment (CVSS, impact, PoC, attack chain)
  ├── 7-Question Validation Gate (false positive elimination)
  └── Priority scoring (exploitability × business impact)
     │
     ▼
Phase 5: REPORT GENERATION
  ├── Individual finding reports (platform-formatted)
  ├── Executive summary
  └── Combined submission report
```

---

## 📋 AI Validation Gate

Each finding must pass a 7-question AI-driven gate:

1. Is the vulnerability genuinely exploitable (not scanner noise)?
2. Can impact be demonstrated with a clear PoC?
3. Is there a realistic attack chain given the target's defenses?
4. Is this a real security boundary bypass (not self-XSS)?
5. Is this novel for this target (not known/expected behavior)?
6. What is the concrete business impact?
7. Would a human triager accept this (not close as informative)?

---

## 🔒 Ethical Use

> **⚠️ WARNING**: This tool is intended for **authorized security testing only**.
> 
> - Only test targets you have **explicit written permission** to test
> - Always comply with bug bounty program scope and rules
> - Unauthorized scanning is illegal under CFAA and similar laws
> - The developers are not responsible for misuse

---

## 📄 Report Platforms

| Platform | Fields Supported |
|----------|-----------------|
| **HackerOne** | Summary, Description, Impact, Steps to Reproduce, CVSS, PoC |
| **Bugcrowd** | Title, Vulnerability Type, Severity, Steps, Impact, PoC |
| **Intigriti** | Title, Description, Impact, PoC, Resolution, CVSS |
| **Immunefi** | Title, Description, Impact, PoC, Risk Classification |

---

## 🛠️ Environment Variables

| Variable | Description |
|----------|-------------|
| `AI_API_KEY` | AI provider API key (OpenAI/Anthropic/Groq) |
| `AI_API_BASE` | Custom API base URL (for proxies/local LLMs) |
| `SECURITYTRAILS_API_KEY` | SecurityTrails API key (optional) |
| `SSRF_CALLBACK_DOMAIN` | OOB callback domain for SSRF testing |

---

*Built with ❤️ for the bug bounty community. Use responsibly.*
