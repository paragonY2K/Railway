package main

import (
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func showHelpMenu(chatID int64, messageID int) {
	helpText := "<b>🔥 WELCOME TO PARAGON SNI PRO!</b>\n" +
		"━━━━━━━━━━━━━━━━━━━━\n\n" +
		"<b>🤔 WHAT DOES THIS BOT DO?</b>\n" +
		"Find free internet tricks (bughosts)\n" +
		"automatically — no manual testing!\n\n" +
		"<b>🚀 QUICK START (3 STEPS):</b>\n" +
		"1️⃣ Send: <code>www.speedtest.net</code>\n" +
		"2️⃣ See result & score\n" +
		"3️⃣ Click <b>💉 Test Payloads</b>\n" +
		"→ DONE! Copy payload to your app!\n\n" +
		"<b>📋 ALL FEATURES:</b>\n" +
		"🔍 <b>Scan</b> — Check if host works\n" +
		"💉 <b>Payload Test</b> — Find working payloads\n" +
		"⚙️ <b>Config Validator</b> — Test your setup!\n" +
		"📊 <b>Mass Scan</b> — Scan 500 hosts at once\n" +
		"🔎 <b>Subdomain</b> — Find related domains\n\n" +
		"<b>💡 TIPS:</b>\n" +
		"• Start with <code>/scan www.speedtest.net</code>\n" +
		"• Green ✅ = good, Red ❌ = dead\n" +
		"• Score 80+ = ready to use!\n" +
		"• Join @supremebughost for help\n\n" +
		"<b>📞 NEED HELP?</b>\n" +
		"Send /feedback — we'll help you!\n\n" +
		"━━━━━━━━━━━━━━━━━━━━\n" +
		"<b>Happy scanning! 🫶</b>"

	msg := tgbotapi.NewMessage(chatID, helpText)
	msg.ParseMode = "HTML"
	msg.ReplyMarkup = getMainMenuOnlyKeyboard()
	bot.Send(msg)
}

func handleHelpCommand(update tgbotapi.Update) {
	chatID := int64(0)
	if update.Message != nil {
		chatID = update.Message.Chat.ID
	} else if update.CallbackQuery != nil {
		chatID = update.CallbackQuery.Message.Chat.ID
	}
	showHelpMenu(chatID, 0)
}
