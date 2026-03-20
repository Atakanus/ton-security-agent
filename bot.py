import os
import httpx
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, filters, ContextTypes

BOT_TOKEN = os.getenv("BOT_TOKEN")
TONCENTER_API_KEY = os.getenv("TONCENTER_API_KEY", "")
TONCENTER_URL = "https://toncenter.com/api/v2"

# Known scam patterns
SCAM_KEYWORDS = ["free ton", "airdrop", "double your ton", "send ton get ton", "investment", "guaranteed profit"]

async def get_wallet_info(address: str) -> dict:
    """Fetch wallet info from TON Center API"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {"X-API-Key": TONCENTER_API_KEY} if TONCENTER_API_KEY else {}
            
            # Get account state
            r = await client.get(f"{TONCENTER_URL}/getAddressInformation", 
                                  params={"address": address}, headers=headers)
            data = r.json()
            
            if not data.get("ok"):
                return {"error": "Invalid address or not found"}
            
            result = data["result"]
            balance_nano = int(result.get("balance", 0))
            balance_ton = balance_nano / 1e9
            state = result.get("state", "unknown")
            
            return {
                "balance": balance_ton,
                "state": state,
                "address": address
            }
    except Exception as e:
        return {"error": str(e)}

async def get_transactions(address: str, limit: int = 10) -> list:
    """Fetch recent transactions"""
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            headers = {"X-API-Key": TONCENTER_API_KEY} if TONCENTER_API_KEY else {}
            r = await client.get(f"{TONCENTER_URL}/getTransactions",
                                  params={"address": address, "limit": limit}, headers=headers)
            data = r.json()
            if data.get("ok"):
                return data["result"]
            return []
    except:
        return []

def analyze_security(wallet_info: dict, transactions: list) -> dict:
    """Analyze wallet for security risks"""
    risks = []
    score = 100  # Start with perfect score
    
    if wallet_info.get("error"):
        return {"score": 0, "risks": ["❌ Address not found or invalid"], "verdict": "INVALID"}
    
    state = wallet_info.get("state", "")
    balance = wallet_info.get("balance", 0)
    
    # Check wallet state
    if state == "uninitialized":
        risks.append("⚠️ Wallet is uninitialized (never used)")
        score -= 10
    
    # Check for suspicious transaction patterns
    if transactions:
        large_outflows = 0
        rapid_txs = 0
        
        for tx in transactions[:10]:
            try:
                out_msgs = tx.get("out_msgs", [])
                for msg in out_msgs:
                    value = int(msg.get("value", 0)) / 1e9
                    if value > 1000:  # Large transfer > 1000 TON
                        large_outflows += 1
                
                # Check for rapid transactions (drain pattern)
                if len(transactions) >= 10:
                    rapid_txs += 1
            except:
                pass
        
        if large_outflows > 3:
            risks.append("🚨 Multiple large outflows detected (possible drain)")
            score -= 30
        
        if rapid_txs >= 10:
            risks.append("⚠️ High transaction frequency (possible bot/scam)")
            score -= 20
        
        # Check if wallet only sends (never receives) - scam pattern
        only_sends = all(len(tx.get("in_msg", {}).get("source", "")) == 0 
                        for tx in transactions[:5] if tx.get("in_msg"))
        if only_sends and len(transactions) > 5:
            risks.append("⚠️ Wallet only sends, never receives (suspicious)")
            score -= 25
    
    if balance == 0 and state != "uninitialized":
        risks.append("⚠️ Zero balance (possibly drained)")
        score -= 15
    
    if not risks:
        risks.append("✅ No suspicious patterns detected")
    
    score = max(0, score)
    
    if score >= 80:
        verdict = "SAFE ✅"
    elif score >= 50:
        verdict = "SUSPICIOUS ⚠️"
    else:
        verdict = "DANGEROUS 🚨"
    
    return {"score": score, "risks": risks, "verdict": verdict}

def check_message_scam(text: str) -> dict:
    """Check if a message contains scam patterns"""
    text_lower = text.lower()
    found_patterns = []
    
    for keyword in SCAM_KEYWORDS:
        if keyword in text_lower:
            found_patterns.append(keyword)
    
    if found_patterns:
        return {
            "is_scam": True,
            "patterns": found_patterns,
            "verdict": "🚨 LIKELY SCAM",
            "advice": "Do NOT send any TON to this address/person!"
        }
    
    return {
        "is_scam": False,
        "patterns": [],
        "verdict": "✅ No obvious scam patterns",
        "advice": "Still be careful — always verify before sending TON"
    }

# ─── TELEGRAM HANDLERS ───────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔍 Check Wallet", callback_data="check_wallet")],
        [InlineKeyboardButton("🛡️ Scan Message", callback_data="scan_message")],
        [InlineKeyboardButton("ℹ️ About", callback_data="about")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "🛡️ *TON Security Agent*\n\n"
        "I protect you from scams and suspicious activity on the TON blockchain.\n\n"
        "*What I can do:*\n"
        "• 🔍 Analyze any TON wallet address\n"
        "• 🚨 Detect scam patterns in messages\n"
        "• 📊 Check transaction history for red flags\n"
        "• ⚠️ Give you a safety score\n\n"
        "Choose an option below or just send me a TON address:",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ *TON Security Agent - Help*\n\n"
        "*Commands:*\n"
        "/start - Main menu\n"
        "/check <address> - Check a TON wallet\n"
        "/scan <message> - Scan text for scams\n"
        "/help - This message\n\n"
        "*Or just send:*\n"
        "• A TON address to check it\n"
        "• Any suspicious message to scan it",
        parse_mode="Markdown"
    )

async def check_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /check <TON_ADDRESS>\n\nExample:\n/check EQD...")
        return
    
    address = context.args[0]
    await process_wallet_check(update, address)

async def process_wallet_check(update: Update, address: str):
    msg = await update.message.reply_text("🔍 Analyzing wallet... please wait")
    
    wallet_info = await get_wallet_info(address)
    transactions = await get_transactions(address)
    analysis = analyze_security(wallet_info, transactions)
    
    score = analysis["score"]
    verdict = analysis["verdict"]
    risks = analysis["risks"]
    
    # Score bar
    filled = int(score / 10)
    bar = "█" * filled + "░" * (10 - filled)
    
    balance = wallet_info.get("balance", "N/A")
    state = wallet_info.get("state", "N/A")
    tx_count = len(transactions)
    
    text = (
        f"🛡️ *Security Analysis*\n\n"
        f"📍 `{address[:8]}...{address[-6:]}`\n\n"
        f"*Safety Score:* {score}/100\n"
        f"`{bar}` {verdict}\n\n"
        f"*Wallet Info:*\n"
        f"💎 Balance: `{balance} TON`\n"
        f"📊 State: `{state}`\n"
        f"📝 Recent txs: `{tx_count}`\n\n"
        f"*Risk Assessment:*\n"
    )
    
    for risk in risks:
        text += f"{risk}\n"
    
    text += "\n_Powered by TON Security Agent_"
    
    await msg.edit_text(text, parse_mode="Markdown")

async def scan_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("Usage: /scan <message text>\n\nSend me a suspicious message to analyze it.")
        return
    
    text = " ".join(context.args)
    result = check_message_scam(text)
    
    response = (
        f"🔍 *Message Scan Result*\n\n"
        f"Verdict: {result['verdict']}\n\n"
    )
    
    if result["patterns"]:
        response += f"*Suspicious patterns found:*\n"
        for p in result["patterns"]:
            response += f"• `{p}`\n"
        response += "\n"
    
    response += f"💡 *Advice:* {result['advice']}"
    
    await update.message.reply_text(response, parse_mode="Markdown")

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()
    
    # Check if it looks like a TON address
    if (text.startswith("EQ") or text.startswith("UQ") or text.startswith("0:")) and len(text) > 30:
        await process_wallet_check(update, text)
    else:
        # Scan as potential scam message
        result = check_message_scam(text)
        
        if result["is_scam"]:
            await update.message.reply_text(
                f"🚨 *Scam Alert!*\n\n{result['verdict']}\n\n"
                f"*Found patterns:* {', '.join(result['patterns'])}\n\n"
                f"💡 {result['advice']}",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(
                "💡 Send me a TON address to check it, or use /help for commands.",
            )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == "check_wallet":
        await query.edit_message_text(
            "🔍 *Check a TON Wallet*\n\n"
            "Send me a TON address to analyze:\n\n"
            "Example: `EQD2NmD_lH5f5u1Kj3KfGyTvhZSX0Eg6qp2a5IQUKXxOG3M`\n\n"
            "Just paste the address in the chat!",
            parse_mode="Markdown"
        )
    elif query.data == "scan_message":
        await query.edit_message_text(
            "🛡️ *Scan a Message*\n\n"
            "Paste any suspicious message and I'll check it for scam patterns.\n\n"
            "Or use: `/scan <message text>`",
            parse_mode="Markdown"
        )
    elif query.data == "about":
        await query.edit_message_text(
            "ℹ️ *About TON Security Agent*\n\n"
            "An AI-powered security tool for the TON ecosystem.\n\n"
            "*Features:*\n"
            "• Wallet risk scoring\n"
            "• Transaction pattern analysis\n"
            "• Scam message detection\n"
            "• Real-time blockchain data\n\n"
            "*Built for:* TON AI Hackathon 2026\n"
            "*Stack:* Python, TON Center API, python-telegram-bot\n\n"
            "Stay safe on TON! 🛡️",
            parse_mode="Markdown"
        )

def main():
    app = Application.builder().token(BOT_TOKEN).build()
    
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_command))
    app.add_handler(CommandHandler("check", check_command))
    app.add_handler(CommandHandler("scan", scan_command))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    
    print("🛡️ TON Security Agent is running...")
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
