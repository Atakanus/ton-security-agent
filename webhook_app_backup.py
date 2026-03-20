import os, json, httpx, asyncio, sqlite3, re
from flask import Flask, request, jsonify

app = Flask(__name__)
BOT_TOKEN = os.getenv("BOT_TOKEN", "")
GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
TONCENTER_URL = "https://toncenter.com/api/v2"
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
DB_PATH = "/home/Atios/ton-security-agent/scamdb.sqlite"

PHISHING_PATTERNS = [
    r'ton-[a-z]+\.(?:xyz|club|top|site|online|click)',
    r'claim-[a-z]+\.(?:xyz|club|top|site)',
    r'[a-z]+-airdrop\.(?:xyz|com|io)',
    r'free-?ton\.(?:xyz|club|top|site|online)',
    r'tonbonus|tonclaim|ton-gift|ton-reward'
]
SCAM_KEYWORDS = ["free ton","airdrop","double your ton","guaranteed profit","multiply","100x","send and receive","limited time","investment"]

# ─── DATABASE ───────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scam_reports
                 (address TEXT, reporter_id INTEGER, category TEXT,
                  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit(); conn.close()

def get_scam_reports(address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*), category FROM scam_reports WHERE address=? GROUP BY category', (address,))
    r = c.fetchall(); conn.close(); return r

def add_scam_report(address, reporter_id, category):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO scam_reports VALUES (?,?,?,CURRENT_TIMESTAMP)', (address, reporter_id, category))
    conn.commit(); conn.close()

def get_top_scams(limit=10):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT address, COUNT(*) as cnt FROM scam_reports GROUP BY address ORDER BY cnt DESC LIMIT ?', (limit,))
    r = c.fetchall(); conn.close(); return r

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM scam_reports')
    total = c.fetchone()[0]
    c.execute('SELECT COUNT(DISTINCT address) FROM scam_reports')
    unique = c.fetchone()[0]
    conn.close()
    return total, unique

# ─── MCP TOOLS ──────────────────────────────────────────────
MCP_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_wallet_info",
            "description": "Get TON wallet balance, state and basic info from blockchain",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "TON wallet address"}
                },
                "required": ["address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_transactions",
            "description": "Get recent transactions for a TON wallet address",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "TON wallet address"},
                    "limit": {"type": "integer", "description": "Number of transactions", "default": 10}
                },
                "required": ["address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_scam_database",
            "description": "Check if a wallet address has been reported as scam by the community",
            "parameters": {
                "type": "object",
                "properties": {
                    "address": {"type": "string", "description": "TON wallet address to check"}
                },
                "required": ["address"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_message",
            "description": "Analyze a text message for scam patterns, phishing links and social engineering",
            "parameters": {
                "type": "object",
                "properties": {
                    "message": {"type": "string", "description": "Message text to analyze"}
                },
                "required": ["message"]
            }
        }
    }
]

# ─── TOOL EXECUTORS ─────────────────────────────────────────
async def execute_tool(name, args):
    if name == "get_wallet_info":
        return await _get_wallet(args["address"])
    elif name == "get_transactions":
        return await _get_txs(args["address"], args.get("limit", 10))
    elif name == "check_scam_database":
        reports = get_scam_reports(args["address"])
        if not reports:
            return {"reported": False, "message": "No reports found"}
        total = sum(r[0] for r in reports)
        cats = [r[1] for r in reports]
        return {"reported": True, "total_reports": total, "categories": cats}
    elif name == "analyze_message":
        msg = args["message"]
        phishing = _check_phishing(msg)
        keywords = [k for k in SCAM_KEYWORDS if k in msg.lower()]
        return {"phishing_links": phishing, "scam_keywords": keywords,
                "suspicious": len(phishing) > 0 or len(keywords) > 0}

async def _get_wallet(address):
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{TONCENTER_URL}/getAddressInformation", params={"address": address})
            d = r.json()
            if not d.get("ok"):
                return {"error": "Invalid address"}
            res = d["result"]
            return {
                "balance_ton": int(res.get("balance", 0)) / 1e9,
                "state": res.get("state", "unknown"),
                "address": address
            }
    except Exception as e:
        return {"error": str(e)}

async def _get_txs(address, limit=10):
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{TONCENTER_URL}/getTransactions",
                           params={"address": address, "limit": limit})
            d = r.json()
            txs = d["result"] if d.get("ok") else []
            return {"count": len(txs), "transactions": txs[:3]}
    except:
        return {"count": 0, "transactions": []}

def _check_phishing(text):
    found = []
    for p in PHISHING_PATTERNS:
        found.extend(re.findall(p, text, re.IGNORECASE))
    for url in re.findall(r'https?://[^\s]+', text):
        for p in PHISHING_PATTERNS:
            if re.search(p, url, re.IGNORECASE) and url not in found:
                found.append(url)
    return found

# ─── MCP AGENT ──────────────────────────────────────────────
async def mcp_agent(user_query, context=""):
    """Agentic loop: AI uses tools to answer security questions"""
    messages = [
        {
            "role": "system",
            "content": """You are TON Security Agent - an expert blockchain security AI.
You have access to tools to check TON wallets and detect scams.
Always use tools to gather data before making assessments.
Be concise. Give a clear SAFE/SUSPICIOUS/DANGEROUS verdict.
Format your final response with emojis for Telegram."""
        },
        {"role": "user", "content": user_query}
    ]

    headers = {
        "Authorization": f"Bearer {GROQ_API_KEY}",
        "Content-Type": "application/json"
    }

    # Agentic loop - max 3 iterations
    for iteration in range(3):
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "tools": MCP_TOOLS,
            "tool_choice": "auto",
            "max_tokens": 1000
        }

        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(GROQ_URL, headers=headers, json=payload)
            data = r.json()

        if "error" in data:
            return f"⚠️ AI error: {data['error'].get('message', 'Unknown')}"

        choice = data["choices"][0]
        msg = choice["message"]
        messages.append(msg)

        # If no tool calls, we have final answer
        if not msg.get("tool_calls"):
            return msg.get("content", "⚠️ No response")

        # Execute all tool calls
        for tool_call in msg["tool_calls"]:
            fn_name = tool_call["function"]["name"]
            fn_args = json.loads(tool_call["function"]["arguments"])

            tool_result = await execute_tool(fn_name, fn_args)

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call["id"],
                "content": json.dumps(tool_result)
            })

    return "⚠️ Analysis timeout"

# ─── TELEGRAM ───────────────────────────────────────────────
async def send_msg(chat_id, text, keyboard=None):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    if keyboard:
        payload["reply_markup"] = json.dumps({"inline_keyboard": keyboard})
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", json=payload)

async def send_typing(chat_id):
    async with httpx.AsyncClient(timeout=5) as c:
        await c.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendChatAction",
                    json={"chat_id": chat_id, "action": "typing"})

async def process_update(update):
    msg = update.get("message", {})
    chat_id = msg.get("chat", {}).get("id")
    user_id = msg.get("from", {}).get("id")
    text = msg.get("text", "").strip()
    if not chat_id or not text:
        return

    if text == "/start":
        await send_msg(chat_id,
            "🛡️ *TON Security Agent*\n\n"
            "AI-powered security for the TON ecosystem.\n\n"
            "*Commands:*\n"
            "/check `<address>` — Analyze wallet\n"
            "/scan `<message>` — Scan for scams\n"
            "/report `<address>` — Report scam wallet\n"
            "/top10 — Most reported scam wallets\n"
            "/stats — Community statistics\n"
            "/help — How to use\n\n"
            "Or just send a TON address directly!")

    elif text == "/help":
        await send_msg(chat_id,
            "📖 *How to use TON Security Agent*\n\n"
            "1️⃣ *Check a wallet:*\n"
            "Send any TON address or use /check\n\n"
            "2️⃣ *Scan a message:*\n"
            "`/scan send me 1 TON get 10 back`\n\n"
            "3️⃣ *Report a scammer:*\n"
            "`/report EQD...address`\n"
            "Then select the scam category\n\n"
            "4️⃣ *See top scams:*\n"
            "/top10\n\n"
            "🤖 Powered by Groq AI + TONCenter API\n"
            "📂 Open source: github.com/Atakanus/ton-security-agent")

    elif text == "/stats":
        total, unique = get_stats()
        await send_msg(chat_id,
            f"📊 *Community Stats*\n\n"
            f"🚨 Total reports: `{total}`\n"
            f"💀 Unique scam wallets: `{unique}`\n\n"
            f"Report scams with /report!")

    elif text == "/top10":
        top = get_top_scams(10)
        if not top:
            await send_msg(chat_id, "📋 No scam reports yet!\n\nBe the first to report with /report")
            return
        lines = ["🏴‍☠️ *Top Reported Scam Wallets*\n"]
        for i, (addr, cnt) in enumerate(top, 1):
            lines.append(f"`{i}.` `{addr[:12]}...` — {cnt} report(s)")
        await send_msg(chat_id, "\n".join(lines))

    elif text.startswith("/check "):
        address = text[7:].strip()
        await send_typing(chat_id)
        await send_msg(chat_id, "🔍 *Analyzing wallet...*\n_AI agent is querying the blockchain_")
        query = f"Analyze this TON wallet address for security risks: {address}"
        result = await mcp_agent(query)
        kb = [[{"text": "🚨 Report this wallet", "callback_data": f"rep_start_{address[:20]}"}]]
        await send_msg(chat_id, result, kb)

    elif text.startswith("/report "):
        address = text[8:].strip()
        if not address:
            await send_msg(chat_id, "Usage: /report <address>"); return
        keyboard = [
            [{"text": "💰 Investment Scam", "callback_data": f"rep_inv_{address[:20]}"},
             {"text": "🎁 Fake Airdrop", "callback_data": f"rep_air_{address[:20]}"}],
            [{"text": "👤 Impersonation", "callback_data": f"rep_imp_{address[:20]}"},
             {"text": "🔧 Fake Support", "callback_data": f"rep_fak_{address[:20]}"}],
            [{"text": "💸 Rugpull", "callback_data": f"rep_rug_{address[:20]}"}]
        ]
        await send_msg(chat_id, f"📋 *Report Wallet*\n`{address[:12]}...`\n\nSelect scam category:", keyboard)

    elif text.startswith("/scan "):
        msg_text = text[6:]
        await send_typing(chat_id)
        await send_msg(chat_id, "🔍 *Scanning message...*")
        query = f"Analyze this message for TON scam patterns: {msg_text}"
        result = await mcp_agent(query)
        await send_msg(chat_id, result)

    elif (text.startswith("EQ") or text.startswith("UQ")) and len(text) > 30:
        await send_typing(chat_id)
        await send_msg(chat_id, "🔍 *Analyzing...*\n_AI agent querying blockchain_")
        query = f"Analyze this TON wallet address for security risks: {text}"
        result = await mcp_agent(query)
        kb = [[{"text": "🚨 Report this wallet", "callback_data": f"rep_start_{text[:20]}"}]]
        await send_msg(chat_id, result, kb)

    else:
        phishing = _check_phishing(text)
        if phishing:
            await send_msg(chat_id, f"🚨 *Phishing link detected!*\n`{phishing[0]}`\n\n⛔ Do NOT click!")

async def process_callback(cb):
    chat_id = cb["message"]["chat"]["id"]
    user_id = cb["from"]["id"]
    data = cb.get("data", "")
    cb_id = cb["id"]

    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(f"https://api.telegram.org/bot{BOT_TOKEN}/answerCallbackQuery",
                    json={"callback_query_id": cb_id})

    if data.startswith("rep_"):
        parts = data.split("_", 2)
        if len(parts) == 3 and parts[1] != "start":
            category_map = {"inv": "investment", "air": "airdrop", "imp": "impersonation",
                          "fak": "fake_support", "rug": "rugpull"}
            category = category_map.get(parts[1], parts[1])
            address = parts[2]
            add_scam_report(address, user_id, category)
            await send_msg(chat_id,
                f"✅ *Reported!*\n`{address[:12]}...` as `{category}`\n\n"
                f"Thank you for keeping TON safe! 🛡️")

# ─── ROUTES ─────────────────────────────────────────────────
@app.route("/")
def index():
    return "TON Security Agent 🛡️ — MCP Edition"

@app.route("/wallet_risk/<address>")
def api_wallet(address):
    async def _get():
        wallet = await _get_wallet(address)
        reports = get_scam_reports(address)
        score = 100
        risks = []
        if wallet.get("state") == "uninitialized":
            risks.append("Never used"); score -= 10
        if wallet.get("balance_ton", 0) == 0 and wallet.get("state") != "uninitialized":
            risks.append("Zero balance"); score -= 15
        if reports:
            total = sum(r[0] for r in reports)
            risks.append(f"{total} scam reports")
            score -= min(50, total * 15)
        score = max(0, score)
        verdict = "SAFE" if score >= 80 else "SUSPICIOUS" if score >= 50 else "DANGEROUS"
        return {"address": address, "score": score, "verdict": verdict,
                "risks": risks, "wallet": wallet}
    return jsonify(asyncio.run(_get()))

@app.route("/webhook", methods=["POST"])
def webhook():
    update = request.get_json()
    if "callback_query" in update:
        asyncio.run(process_callback(update["callback_query"]))
    else:
        asyncio.run(process_update(update))
    return "ok", 200

init_db()
