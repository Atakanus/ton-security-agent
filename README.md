# 🛡️ TON Security Agent

An AI-native security agent for the TON ecosystem. Protects users from scams, phishing attacks, and malicious wallets — all inside Telegram.

Built for **TON AI Hackathon 2026 — Track 1: Agent Infrastructure**

🤖 **Try it live:** [@TONSecurityAgentBot](https://t.me/TONSecurityAgentBot)

---

## Features

- 🔍 **Wallet Analysis** — AI agent queries the blockchain and analyzes any TON address
- 🚨 **Scam Detection** — Scan messages for phishing links and social engineering patterns
- 🤖 **MCP-Inspired Agentic Loop** — AI autonomously calls tools (wallet info, transactions, scam DB) to generate security assessments
- 📊 **Safety Score** — 0-100 risk score for any wallet
- 👥 **Community Scam Database** — Users report scam wallets by category
- 🏴‍☠️ **Top Scam Wallets** — Community-powered leaderboard of most reported addresses
- 🌐 **Public REST API** — Developers can integrate wallet risk scoring into their own apps

---

## Commands

| Command | Description |
|---|---|
| `/check <address>` | Analyze a TON wallet with AI |
| `/scan <message>` | Scan text for scam patterns |
| `/report <address>` | Report a scam wallet |
| `/top10` | Most reported scam wallets |
| `/stats` | Community statistics |
| `/help` | How to use |

---

## Architecture

```
User → Telegram Bot → MCP Agentic Loop
                           ↓
                    Groq AI (Llama 3.3 70B)
                    ↙        ↓        ↘
             TONCenter   Scam DB   Phishing
               API       SQLite    Scanner
```

The AI agent autonomously decides which tools to call, executes them, and synthesizes results — no hardcoded logic.

---

## Public API

```
GET https://atios.pythonanywhere.com/wallet_risk/<address>
```

**Response:**
```json
{
  "address": "UQC...",
  "score": 85,
  "verdict": "SAFE",
  "risks": []
}
```

---

## Tech Stack

- **AI:** Groq API — `llama-3.3-70b-versatile`
- **Bot:** Python + Flask (webhook)
- **Blockchain:** TONCenter API v2
- **Database:** SQLite (community scam reports)
- **Hosting:** PythonAnywhere (free tier, 24/7)

---

## Setup

```bash
git clone https://github.com/Atakanus/ton-security-agent
cd ton-security-agent
pip install -r requirements.txt
```

Environment variables:
```
BOT_TOKEN=your_telegram_bot_token
GROQ_API_KEY=your_groq_api_key
```

---

## Why This Matters

For Web3 to reach mass adoption, security must be invisible. By embedding AI-powered safety directly into Telegram — the primary entry point for TON users — this agent provides the infrastructure layer that gives users confidence to transact freely.

---

*Built with ❤️ for the TON ecosystem*
