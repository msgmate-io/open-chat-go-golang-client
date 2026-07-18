package goclient

import (
	"encoding/json"
	"fmt"
	"strings"
)

func FormatPaginatedChatsReadable(chats PaginatedChats) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Chats page=%d limit=%d total_pages=%d\n", chats.Page, chats.Limit, chats.TotalPages)

	if len(chats.Rows) == 0 {
		b.WriteString("No chats found.")
		return b.String(), nil
	}

	for i, row := range chats.Rows {
		fmt.Fprintf(&b, "%d) %s\n", i+1, buildChatHeadline(row))
		fmt.Fprintf(&b, "   uuid: %s\n", fallback(row.UUID, "-"))
		fmt.Fprintf(&b, "   latest: %s", buildLatestPreview(row.LatestMessage))
		if i < len(chats.Rows)-1 {
			b.WriteString("\n")
		}
	}

	return b.String(), nil
}

func FormatListedChatReadable(chat ListedChat) (string, error) {
	var b strings.Builder
	b.WriteString("Chat\n")
	fmt.Fprintf(&b, "uuid: %s\n", fallback(chat.UUID, "-"))
	fmt.Fprintf(&b, "type: %s\n", fallback(chat.ChatType, "unknown"))
	fmt.Fprintf(&b, "partner: %s\n", buildPartnerLabel(chat.Partner))
	fmt.Fprintf(&b, "latest: %s", buildLatestPreview(chat.LatestMessage))

	if strings.TrimSpace(chat.ChatShareUUID) != "" {
		fmt.Fprintf(&b, "\nshare_uuid: %s", chat.ChatShareUUID)
	}
	if strings.TrimSpace(chat.SharedChatURL) != "" {
		fmt.Fprintf(&b, "\nshare_url: %s", chat.SharedChatURL)
	}

	return b.String(), nil
}

func FormatPaginatedMessagesReadable(messages PaginatedMessages) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "Messages page=%d limit=%d total_pages=%d\n", messages.Page, messages.Limit, messages.TotalPages)

	if len(messages.Rows) == 0 {
		b.WriteString("No messages found.")
		return b.String(), nil
	}

	for i, row := range messages.Rows {
		fmt.Fprintf(&b, "%d) %s\n", i+1, fallback(row.UUID, "-"))
		fmt.Fprintf(&b, "   send_at: %s\n", fallback(row.SendAt, "-"))
		senderKind := "human"
		if row.SenderIsAutomated {
			senderKind = "automated"
		}
		fmt.Fprintf(&b, "   sender: %s (%s)\n", fallback(row.SenderUUID, "-"), senderKind)
		fmt.Fprintf(&b, "   type: %s\n", fallback(row.DataType, "unknown"))
		fmt.Fprintf(&b, "   text: %s", fallback(cleanInline(row.Text), "-"))
		if i < len(messages.Rows)-1 {
			b.WriteString("\n")
		}
	}

	return b.String(), nil
}

func buildChatHeadline(chat ListedChat) string {
	chatType := fallback(chat.ChatType, "unknown")
	partner := buildPartnerLabel(chat.Partner)
	return fmt.Sprintf("[%s] %s", chatType, partner)
}

func buildPartnerLabel(partner interface{}) string {
	switch typed := partner.(type) {
	case string:
		return fallback(cleanInline(typed), "unknown")
	case map[string]interface{}:
		label := firstNonEmptyString(typed, "name", "display_name", "email", "username", "user_uuid", "uuid", "contact_token")
		if label != "" {
			return cleanInline(label)
		}
		return fallback(compactJSON(typed), "unknown")
	default:
		return fallback(compactJSON(typed), "unknown")
	}
}

func buildLatestPreview(latest interface{}) string {
	switch typed := latest.(type) {
	case nil:
		return "-"
	case string:
		return fallback(cleanInline(typed), "-")
	case map[string]interface{}:
		text := firstNonEmptyString(typed, "text", "content", "message", "body")
		if text != "" {
			return cleanInline(text)
		}
		return fallback(compactJSON(typed), "-")
	default:
		return fallback(compactJSON(typed), "-")
	}
}

func firstNonEmptyString(values map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		raw, ok := values[key]
		if !ok {
			continue
		}
		value, ok := raw.(string)
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func cleanInline(value string) string {
	replacer := strings.NewReplacer("\n", " ", "\r", " ", "\t", " ")
	cleaned := replacer.Replace(strings.TrimSpace(value))
	cleaned = strings.Join(strings.Fields(cleaned), " ")
	if cleaned == "" {
		return ""
	}
	const maxLen = 120
	if len(cleaned) > maxLen {
		return cleaned[:maxLen-3] + "..."
	}
	return cleaned
}

func compactJSON(value interface{}) string {
	if value == nil {
		return ""
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(raw)
}

func fallback(value, defaultValue string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultValue
	}
	return trimmed
}
