# 🛡️ TON Security Agent

An AI-powered security bot for the TON ecosystem. Protects users from scams, suspicious wallets, and malicious activity on the TON blockchain.

## Features

- 🔍 **Wallet Analysis** — Check any TON address for suspicious patterns
- 🚨 **Scam Detection** — Scan messages for known scam patterns  
- 📊 **Safety Score** — Get a 0-100 risk score for any wallet
- ⚡ **Real-time** — Live data from TON Center API

## Commands

- `/start` — Main menu
- `/check <address>` — Analyze a TON wallet
- `/scan <message>` — Scan text for scam patterns
- `/help` — Help

## Setup

### Local

```bash
git clone https://github.com/yourusername/ton-security-agent
cd ton-security-agent
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your tokens
python bot.py
```

### Railway Deploy

1. Fork this repo
2. Connect to Railway
3. Add environment variables:
   - `BOT_TOKEN` — from @BotFather
   - `TONCENTER_API_KEY` — from toncenter.com (optional)
4. Deploy!

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BOT_TOKEN` | ✅ | Telegram bot token from @BotFather |
| `TONCENTER_API_KEY` | ⚪ | TON Center API key (optional, for higher rate limits) |

## Built For

TON AI Hackathon 2026 — Track 1: Agent Infrastructure

## Tech Stack

- Python 3.11
- python-telegram-bot 21.3
- httpx
- TON Center API v2
