package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// =============================================
// FEEDBACK SYSTEM - COMPLETE
// =============================================

func handleFeedback(update tgbotapi.Update) {
	chatID := getUserID(update)

	text := "💬 *Feedback / Thank You*\n" +
		"━━━━━━━━━━━━━━━━━━━━\n\n" +
		"Your words mean a lot! 🫶\n\n" +
		"Just type your message:\n" +
		"• Suggestion\n" +
		"• Bug report\n" +
		"• Or just say thanks 😊\n\n" +
		"_Type 'cancel' to go back_"

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = getCancelKeyboard()
	bot.Send(msg)

	setSessionState(chatID, "awaiting_feedback")
}

func handleFeedbackInput(update tgbotapi.Update) {
	chatID := update.Message.Chat.ID
	text := strings.TrimSpace(update.Message.Text)
	username := getUserName(update)

	if text == "" || strings.ToLower(text) == "cancel" {
		clearSessionState(chatID)
		msg := tgbotapi.NewMessage(chatID, "👋 No worries! Back to main menu.")
		bot.Send(msg)
		return
	}

	// Save feedback
	saveFeedback(chatID, username, text)

	// Reply to user
	reply := "🙏 *Thank You!*\n" +
		"━━━━━━━━━━━━━━━━━━━━\n\n" +
		"Your feedback has been saved. 💾\n\n"

	if containsThanks(text) {
		reply += "And... thank YOU for using Paragon PRO! 🫶\n" +
			"It means a lot to the developer.\n"
	} else {
		reply += "The developer will review it. 🛠️\n" +
			"Thank you for helping improve the bot!\n"
	}

	reply += "\n_Send /start to return to menu_"

	msg := tgbotapi.NewMessage(chatID, reply)
	msg.ParseMode = "Markdown"
	bot.Send(msg)

	// Notify admin
	notifyAdminFeedback(chatID, username, text)

	clearSessionState(chatID)
}

func saveFeedback(chatID int64, username, text string) {
	feedbackDir := "/tmp/paragon_feedback"
	os.MkdirAll(feedbackDir, 0755)

	filename := fmt.Sprintf("%s/feedback_%s.txt",
		feedbackDir,
		time.Now().Format("20060102"))

	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	entry := fmt.Sprintf("[%s] User: %d (@%s)\n%s\n\n",
		time.Now().Format("15:04:05"),
		chatID,
		username,
		text)

	f.WriteString(entry)
}

func notifyAdminFeedback(chatID int64, username, text string) {
	adminMsg := fmt.Sprintf(
		"📬 *New Feedback*\n"+
			"━━━━━━━━━━━━━━━━━━━━\n"+
			"*From:* `%d` (@%s)\n"+
			"*Message:* %s",
		chatID, username, text,
	)

	msg := tgbotapi.NewMessage(adminChatID, adminMsg)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}

func containsThanks(text string) bool {
	lower := strings.ToLower(text)
	thanksWords := []string{
		"thanks", "thank", "best", "thx", "ty",
		"power", "best", "bagus", "mantap", "good", "👍",
		"love", "suka", "terbaik", "padu", "gempak",
	}
	for _, word := range thanksWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// =============================================
// AUTO-THANK YOU PROMPT (After Scan)
// =============================================

func appendThankYouPrompt(chatID int64) {
	prompt := "💡 *Enjoying Paragon PRO?*\n" +
		"Send /feedback — your words keep me going! 🫶"

	msg := tgbotapi.NewMessage(chatID, prompt)
	msg.ParseMode = "Markdown"
	bot.Send(msg)
}
