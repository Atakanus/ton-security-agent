
def add_watchlist(user_id, address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS watchlist (user_id INTEGER, address TEXT, last_balance REAL, last_tx_count INTEGER, PRIMARY KEY(user_id, address))")
    c.execute("INSERT OR IGNORE INTO watchlist (user_id, address, last_balance, last_tx_count) VALUES (?, ?, 0, 0)", (user_id, address))
    conn.commit()
    conn.close()

def get_watchlist(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS watchlist (user_id INTEGER, address TEXT, last_balance REAL, last_tx_count INTEGER, PRIMARY KEY(user_id, address))")
    c.execute("SELECT address FROM watchlist WHERE user_id=?", (user_id,))
    rows = c.fetchall()
    conn.close()
    return [r[0] for r in rows]

def remove_watchlist(user_id, address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM watchlist WHERE user_id=? AND address=?", (user_id, address))
    conn.commit()
    conn.close()

def update_watchlist(user_id, address, balance, tx_count):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("UPDATE watchlist SET last_balance=?, last_tx_count=? WHERE user_id=? AND address=?", (balance, tx_count, user_id, address))
    conn.commit()
    conn.close()

def get_watchlist_data(user_id, address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT last_balance, last_tx_count FROM watchlist WHERE user_id=? AND address=?", (user_id, address))
    row = c.fetchone()
    conn.close()
    return row
import os, json, httpx, asyncio, sqlite3, re
from flask import Flask, request, jsonify

app = Flask(__name__)
last_request = {}
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

def add_safe_vote(address, user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS safe_votes 
                 (address TEXT, user_id INTEGER, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)""")
    c.execute('INSERT INTO safe_votes VALUES (?,?,CURRENT_TIMESTAMP)', (address, user_id))
    conn.commit(); conn.close()

def get_safe_votes(address):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute('SELECT COUNT(*) FROM safe_votes WHERE address=?', (address,))
        r = c.fetchone()[0]
    except:
        r = 0
    conn.close()
    return r

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


# ─── LANGUAGE SYSTEM ────────────────────────────────────────
def init_lang_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS user_lang
                 (user_id INTEGER PRIMARY KEY, lang TEXT DEFAULT \'en\')''')
    conn.commit(); conn.close()

def get_lang(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT lang FROM user_lang WHERE user_id=?', (user_id,))
    r = c.fetchone()
    conn.close()
    return r[0] if r else 'en'

def set_lang(user_id, lang):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR REPLACE INTO user_lang (user_id, lang) VALUES (?,?)', (user_id, lang))
    conn.commit(); conn.close()


def register_user(user_id, lang='en'):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT OR IGNORE INTO users (user_id, lang) VALUES (?,?)', (user_id, lang))
    conn.commit(); conn.close()

def get_user_count():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM users')
    total = c.fetchone()[0]
    c.execute("SELECT COUNT(*) FROM users WHERE first_seen >= datetime('now', '-7 days')")
    weekly = c.fetchone()[0]
    conn.close()
    return total, weekly

TEXTS = {
    'en': {
        'start': "🛡️ *TON Security Agent*\n\nAI-powered security for the TON ecosystem.\n\n*Commands:*\n/check `<address>` — Analyze wallet\n/scan `<message>` — Scan for scams\n/report `<address>` — Report scam wallet\n/ai <question> — Ask AI\n/watchlist <address> — Watch wallet changes\n/top10 — Most reported scam wallets\n/stats — Community statistics\n/help — How to use\n/lang — Change language\n\nOr just send a TON address directly!",
        'help': "📖 *How to use TON Security Agent*\n\n1️⃣ *Check a wallet:*\nSend any TON address or use /check\n\n2️⃣ *Scan a message:*\n`/scan send me 1 TON get 10 back`\n\n3️⃣ *Report a scammer:*\n`/report EQD...address`\nThen select the scam category\n\n4️⃣ *See top scams:*\n/top10\n\n🤖 Powered by Groq AI + TONCenter API\n📂 github.com/Atakanus/ton-security-agent",
        'analyzing': "🔍 *Analyzing wallet...*\n_AI agent is querying the blockchain_",
        'scanning': "🔍 *Scanning message...*",
        'stats': "📊 *Community Stats*\n\n👥 Total users: `{users}`\n📈 Weekly active: `{weekly}`\n\n🚨 Total reports: `{total}`\n💀 Unique scam wallets: `{unique}`\n\nReport scams with /report!",
        'no_reports': "📋 No scam reports yet!\n\nBe the first to report with /report",
        'top_title': "🏴‍☠️ *Top Reported Scam Wallets*\n",
        'report_title': "📋 *Report Wallet*\n`{addr}`\n\nSelect scam category:",
        'reported': "✅ *Reported!*\n`{addr}` as `{cat}`\n\nThank you for keeping TON safe! 🛡️",
        'report_btn': ["💰 Investment Scam", "🎁 Fake Airdrop", "👤 Impersonation", "🔧 Fake Support", "💸 Rugpull"],
        'lang_select': "🌐 *Select Language:*",
        'lang_set': "✅ Language set to English!",
    },
    'ru': {
        'start': "🛡️ *TON Security Agent*\n\nИИ-защита для экосистемы TON.\n\n*Команды:*\n/check `<адрес>` — Анализ кошелька\n/scan `<сообщение>` — Проверка на скам\n/report `<адрес>` — Сообщить о скаме\n/top10 — Топ скам-кошельков\n/stats — Статистика\n/help — Помощь\n/lang — Сменить язык\n\nИли просто отправьте TON-адрес!",
        'help': "📖 *How to use TON Security Agent*\n\n1️⃣ *Check a wallet:*\nSend any TON address or use /check\n\n2️⃣ *Scan a message:*\n`/scan send me 1 TON get 10 back`\n\n3️⃣ *Report a scammer:*\n`/report EQD...address`\nThen select the scam category\n\n4️⃣ *See top scams:*\n/top10\n\n🤖 Powered by Groq AI + TONCenter API\n📂 github.com/Atakanus/ton-security-agent",
        'analyzing': "🔍 *Анализирую кошелёк...*\n_ИИ запрашивает блокчейн_",
        'scanning': "🔍 *Проверяю сообщение...*",
        'stats': "📊 *Статистика сообщества*\n\n👥 Пользователей: `{users}`\n📈 За неделю: `{weekly}`\n\n🚨 Всего жалоб: `{total}`\n💀 Скам-кошельков: `{unique}`\n\nСообщайте о скамах: /report",
        'no_reports': "📋 Жалоб пока нет!\n\nБудьте первым: /report",
        'top_title': "🏴‍☠️ *Топ скам-кошельков*\n",
        'report_title': "📋 *Сообщить о кошельке*\n`{addr}`\n\nВыберите тип:",
        'reported': "✅ *Жалоба отправлена!*\n`{addr}` — `{cat}`\n\nСпасибо за защиту TON! 🛡️",
        'report_btn': ["💰 Инвест-скам", "🎁 Фейк аирдроп", "👤 Имперсонация", "🔧 Фейк поддержка", "💸 Ругпул"],
        'lang_select': "🌐 *Выберите язык:*",
        'lang_set': "✅ Язык изменён на Русский!",
    },
    'zh': {
        'start': "🛡️ *TON Security Agent*\n\nTON生态系统的AI安全防护。\n\n*命令:*\n/check `<地址>` — 分析钱包\n/scan `<消息>` — 扫描诈骗\n/report `<地址>` — 举报诈骗\n/top10 — 最多举报钱包\n/stats — 社区统计\n/help — 帮助\n/lang — 切换语言\n\n或直接发送TON地址！",
        'help': "📖 *How to use TON Security Agent*\n\n1️⃣ *Check a wallet:*\nSend any TON address or use /check\n\n2️⃣ *Scan a message:*\n`/scan send me 1 TON get 10 back`\n\n3️⃣ *Report a scammer:*\n`/report EQD...address`\nThen select the scam category\n\n4️⃣ *See top scams:*\n/top10\n\n🤖 Powered by Groq AI + TONCenter API\n📂 github.com/Atakanus/ton-security-agent",
        'analyzing': "🔍 *分析钱包中...*\n_AI正在查询区块链_",
        'scanning': "🔍 *扫描消息中...*",
        'stats': "📊 *社区统计*\n\n👥 总用户数: `{users}`\n📈 本周活跃: `{weekly}`\n\n🚨 总举报数: `{total}`\n💀 诈骗钱包: `{unique}`\n\n用 /report 举报！",
        'no_reports': "📋 暂无举报！\n\n使用 /report 成为第一个举报者",
        'top_title': "🏴‍☠️ *最多举报诈骗钱包*\n",
        'report_title': "📋 *举报钱包*\n`{addr}`\n\n选择类型:",
        'reported': "✅ *已举报！*\n`{addr}` — `{cat}`\n\n感谢保护TON安全！🛡️",
        'report_btn': ["💰 投资诈骗", "🎁 假空投", "👤 冒充他人", "🔧 假客服", "💸 跑路"],
        'lang_select': "🌐 *选择语言:*",
        'lang_set': "✅ 语言已切换为中文！",
    }
}

def t(user_id, key, **kwargs):
    lang = get_lang(user_id)
    text = TEXTS.get(lang, TEXTS['en']).get(key, TEXTS['en'].get(key, key))
    if kwargs:
        text = text.format(**kwargs)
    return text


async def format_wallet_analysis(address, wallet, txs, reports, safe_votes=0):
    balance = wallet.get("balance_ton", 0)
    state = wallet.get("state", "unknown")
    tx_count = txs.get("count", 0)
    total_reports = sum(r[0] for r in reports) if reports else 0
    categories = [r[1] for r in reports] if reports else []

    score = 100
    threats = []

    if total_reports > 0:
        score -= min(60, total_reports * 15)
        threats.append(f"🚫 Reported by {total_reports} community member(s): {', '.join(categories)}")
    if state == "uninitialized":
        score -= 10
        threats.append("⚠️ Wallet never activated")
    if balance == 0 and state == "active":
        score -= 15
        threats.append("💸 Balance drained to zero")
    if tx_count > 100:
        score -= 10
        threats.append("🔍 Abnormal transaction volume")

    if safe_votes > 0:
        effective_reports = max(0, total_reports - safe_votes * 2)
    effective_reports = 0
    if reports:
        total_r = sum(r[0] for r in reports)
        safe_v = get_safe_votes(address) if callable(get_safe_votes) else 0
        effective_reports = max(0, total_r - safe_v * 2)
    if reports and effective_reports > 0:
        score -= min(60, effective_reports * 15)
    score = max(0, score)
    pattern_matches = min(3, total_reports) if total_reports > 0 else 0

    if score >= 80:
        confidence = min(99, 85 + tx_count // 10)
        verdict_emoji = "🟢"
        verdict_text = "SAFE"
    elif score >= 50:
        confidence = min(99, 60 + total_reports * 5)
        verdict_emoji = "🟡"
        verdict_text = "SUSPICIOUS"
    else:
        confidence = min(99, 75 + total_reports * 5)
        verdict_emoji = "🔴"
        verdict_text = "CRITICAL"

    risk = 100 - score
    filled = risk // 10
    bar = "█" * filled + "░" * (10 - filled)
    short_addr = f"{address[:10]}...{address[-6:]}"

    lines = [
        f"🛡️ *TON SECURITY AGENT — AI ANALYSIS*\n",
        f"📍 `{short_addr}`\n",
        f"{verdict_emoji} *RISK SCORE: {risk}/100*",
        f"`[{bar}]`\n",
        f"🤖 *SCAM PROBABILITY: {verdict_text}* {verdict_emoji}",
        f"📊 AI Confidence: {confidence}%\n",
    ]

    if threats:
        lines.append("🚨 *THREAT ASSESSMENT:*")
        for t in threats:
            lines.append(t)
        lines.append("")

    if pattern_matches > 0:
        lines.append(f"🔍 Matches {pattern_matches} known scam pattern(s)\n")

    lines.extend([
        "📈 *WALLET HEALTH:*",
        f"• Balance: `{balance:.2f} TON`",
        f"• State: `{state}`",
        f"• Transactions: `{tx_count}`",
    ])

    return "\n".join(lines)

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
    import time
    now = time.time()
    if last_request.get(user_id, 0) > now - 3:
        return
    last_request[user_id] = now

    if text == "/start":
        register_user(user_id)
        lang_kb = [[
            {"text": "🇬🇧 English", "callback_data": "lang_en"},
            {"text": "🇷🇺 Русский", "callback_data": "lang_ru"},
            {"text": "🇨🇳 中文", "callback_data": "lang_zh"}
        ]]
        await send_msg(chat_id, t(user_id, 'start'), lang_kb)

    elif text == "/lang":
        lang_kb = [[
            {"text": "🇬🇧 English", "callback_data": "lang_en"},
            {"text": "🇷🇺 Русский", "callback_data": "lang_ru"},
            {"text": "🇨🇳 中文", "callback_data": "lang_zh"}
        ]]
        await send_msg(chat_id, t(user_id, 'lang_select'), lang_kb)

    elif text == "/help":
        await send_msg(chat_id, t(user_id, 'help'))

    elif text == "/stats":
        total, unique = get_stats()
        users, weekly = get_user_count()
        await send_msg(chat_id, t(user_id, 'stats', total=total, unique=unique, users=users, weekly=weekly))

    elif text == "/top10":
        top = get_top_scams(10)
        if not top:
            await send_msg(chat_id, t(user_id, 'no_reports'))
            return
        lines = [t(user_id, 'top_title')]
        for i, (addr, cnt) in enumerate(top, 1):
            lines.append(f"`{i}.` `{addr[:12]}...` — {cnt} report(s)")
        await send_msg(chat_id, "\n".join(lines))
    elif text.startswith('/ai '):
        query = text[4:].strip()
        await send_typing(chat_id)
        async with httpx.AsyncClient() as c:
            r = await c.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {GROQ_API_KEY}"},
                json={
                    "model": "llama-3.3-70b-versatile",
                    "messages": [
                        {"role": "system", "content": "You are a TON blockchain security expert and assistant for TON Security Agent bot. This bot was created by Atakan Coskun, a Turkish security researcher and developer. Be concise."},
                        {"role": "user", "content": query}
                    ],
                    "max_tokens": 300
                },
                timeout=15
            )
            answer = r.json()["choices"][0]["message"]["content"]
            await send_msg(chat_id, f"🤖 AI:\n\n{answer}")

    elif text.startswith("/watchlist"):
        parts = text.split()
        if len(parts) == 1:
            wl = get_watchlist(user_id)
            if not wl:
                await send_msg(chat_id, "📋 Watchlist bos. Kullanim: /watchlist <adres>")
            else:
                msg = "👁 Watchlist:\n\n" + "\n".join([f"{a[:25]}..." for a in wl])
                await send_msg(chat_id, msg)
        elif len(parts) == 2:
            add_watchlist(user_id, parts[1].strip())
            await send_msg(chat_id, "✅ Watchliste eklendi!")
    elif text.startswith("/unwatch"):
        parts = text.split()
        if len(parts) == 2:
            remove_watchlist(user_id, parts[1].strip())
            await send_msg(chat_id, "✅ Watchlistten silindi.")
    elif text.startswith("/check "):
        address = text[7:].strip()
        await send_typing(chat_id)
        await send_msg(chat_id, t(user_id, 'analyzing'))
        wallet = await _get_wallet(address)
        txs = await _get_txs(address)
        reports = get_scam_reports(address)
        votes = get_safe_votes(address)
        result = await format_wallet_analysis(address, wallet, txs, reports, votes)
        kb = [[{"text": "📋 Watchlist", "callback_data": "watchlist"}, {"text": "🚨 Report this wallet", "callback_data": f"rep_inv_{address}"},
               {"text": "✅ Looks Safe", "callback_data": f"safe_{address}"}]]
        await send_msg(chat_id, result, kb)

    elif text.startswith("/report "):
        address = text[8:].strip()
        if not address:
            await send_msg(chat_id, "Usage: /report <address>"); return
        btns = t(user_id, 'report_btn')
        keyboard = [
            [{"text": btns[0], "callback_data": f"rep_inv_{address}"},
             {"text": btns[1], "callback_data": f"rep_air_{address}"}],
            [{"text": btns[2], "callback_data": f"rep_imp_{address}"},
             {"text": btns[3], "callback_data": f"rep_fak_{address}"}],
            [{"text": btns[4], "callback_data": f"rep_rug_{address}"}]
        ]
        await send_msg(chat_id, t(user_id, 'report_title', addr=address[:12]+'...'), keyboard)

    elif text.startswith("/scan "):
        msg_text = text[6:]
        await send_typing(chat_id)
        await send_msg(chat_id, t(user_id, 'scanning'))
        query = f"Analyze this message for TON scam patterns: {msg_text}"
        result = await mcp_agent(query)
        await send_msg(chat_id, result)

    elif (text.startswith("EQ") or text.startswith("UQ")) and len(text) > 30:
        await send_typing(chat_id)
        await send_msg(chat_id, "🔍 *Analyzing...*\n_AI agent querying blockchain_")
        wallet = await _get_wallet(text)
        txs = await _get_txs(text)
        reports = get_scam_reports(text)
        result = await format_wallet_analysis(text, wallet, txs, reports)
        kb = [[{"text": "🚨 Report this wallet", "callback_data": f"rep_inv_{text[:20]}"},
               {"text": "✅ Looks Safe", "callback_data": f"safe_{text[:20]}"}]]
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

    if data.startswith("lang_"):
        lang = data.split("_")[1]
        set_lang(user_id, lang)
        lang_names = {"en": "✅ Language set to English!", "ru": "✅ Язык изменён на Русский!", "zh": "✅ 语言已切换为中文！"}
        await send_msg(chat_id, lang_names.get(lang, "✅ Done!"))

    elif data.startswith("safe_"):
        address = data[5:]
        add_safe_vote(address, user_id)
        await send_msg(chat_id, "✅ Marked as safe! Thank you 🛡️")

    elif data.startswith("rep_"):
        parts = data.split("_", 2)
        if len(parts) == 3 and parts[1] != "start":
            category_map = {"inv": "investment", "air": "airdrop", "imp": "impersonation",
                          "fak": "fake_support", "rug": "rugpull"}
            category = category_map.get(parts[1], parts[1])
            address = parts[2]
            add_scam_report(address, user_id, category)
            await send_msg(chat_id, t(user_id, 'reported', addr=address[:12]+'...', cat=category))

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
init_lang_db()

def init_users_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, first_seen DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit(); conn.close()

init_users_db()
