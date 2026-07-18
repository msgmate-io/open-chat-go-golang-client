package goclient

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"

	generatedapi "github.com/msgmate-io/go-client-integration/generated_api"
)

type SendMessage struct {
	Text      string                  `json:"text"`
	Reasoning []string                `json:"reasoning"`
	MetaData  *map[string]interface{} `json:"meta_data,omitempty"`
	ToolCalls *[]interface{}          `json:"tool_calls,omitempty"`
}

type FileAttachment struct {
	FileID      string `json:"file_id"`
	DisplayName string `json:"display_name,omitempty"`
	FileName    string `json:"file_name,omitempty"`
	FileSize    int64  `json:"file_size,omitempty"`
	MimeType    string `json:"mime_type,omitempty"`
}

type ListedContact struct {
	ContactToken string                 `json:"contact_token"`
	Name         string                 `json:"name"`
	UserUUID     string                 `json:"user_uuid"`
	IsOnline     bool                   `json:"is_online"`
	IsAutomated  bool                   `json:"is_automated"`
	ProfileData  map[string]interface{} `json:"profile_data"`
}

type PaginatedContacts struct {
	Limit      int             `json:"limit"`
	Page       int             `json:"page"`
	TotalPages int             `json:"total_pages"`
	Rows       []ListedContact `json:"rows"`
}

type User struct {
	UUID string `json:"uuid"`
}

type ListedChat struct {
	UUID          string      `json:"uuid"`
	Partner       interface{} `json:"partner"`
	LatestMessage interface{} `json:"latest_message"`
	ChatType      string      `json:"chat_type"`
	Config        interface{} `json:"config"`
	ChatShareUUID string      `json:"chat_share_uuid,omitempty"`
	SharedChatURL string      `json:"shared_interaction_url,omitempty"`
}

type PaginatedChats struct {
	Limit      int          `json:"limit"`
	Page       int          `json:"page"`
	TotalPages int          `json:"total_pages"`
	Rows       []ListedChat `json:"rows"`
}

type ListedMessage struct {
	UUID              string                  `json:"uuid"`
	SendAt            string                  `json:"send_at"`
	SenderID          uint                    `json:"sender_id"`
	ReceiverID        uint                    `json:"receiver_id"`
	SenderUUID        string                  `json:"sender_uuid"`
	SenderIsAutomated bool                    `json:"sender_is_automated"`
	DataType          string                  `json:"data_type"`
	Text              string                  `json:"text"`
	Reasoning         *[]string               `json:"reasoning"`
	ToolCalls         *[]interface{}          `json:"tool_calls"`
	MetaData          *map[string]interface{} `json:"meta_data"`
}

type PaginatedMessages struct {
	Limit      int             `json:"limit"`
	Page       int             `json:"page"`
	TotalPages int             `json:"total_pages"`
	Rows       []ListedMessage `json:"rows"`
}

type Client struct {
	host        string
	sessionID   string
	accessToken string
	api         *generatedapi.ClientWithResponses
	initErr     error
	apiKeys     map[string]string
	User        User
}

func NewClient(host string) *Client {
	normalizedHost := strings.TrimSpace(host)
	normalizedHost = strings.TrimRight(normalizedHost, "/")
	if normalizedHost == "" {
		normalizedHost = "http://localhost:1984"
	}

	client := &Client{
		host: normalizedHost,
		apiKeys: map[string]string{
			"deepinfra": os.Getenv("DEEPINFRA_API_KEY"),
			"openai":    os.Getenv("OPENAI_API_KEY"),
			"groq":      os.Getenv("GROQ_API_KEY"),
			"litellm":   os.Getenv("LITELLM_API_KEY"),
			"anthropic": os.Getenv("ANTHROPIC_API_KEY"),
		},
	}
	api, err := generatedapi.NewClientWithResponses(normalizedHost, generatedapi.WithRequestEditorFn(client.requestEditor))
	if err != nil {
		client.initErr = fmt.Errorf("failed to create Open Chat generated client: %w", err)
		return client
	}
	client.api = api
	return client
}

func (c *Client) requestEditor(_ context.Context, req *http.Request) error {
	req.Header.Set("Origin", c.host)
	if c.accessToken != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	}
	if c.sessionID != "" {
		req.Header.Set("Cookie", fmt.Sprintf("session_id=%s", c.sessionID))
	}
	return nil
}

func (c *Client) SetSessionId(sessionID string) {
	c.sessionID = strings.TrimSpace(sessionID)
}

func (c *Client) SetAccessToken(token string) {
	c.accessToken = strings.TrimSpace(token)
}

func (c *Client) GetSessionId() string {
	return c.sessionID
}

func (c *Client) GetHost() string {
	return c.host
}

func (c *Client) LoginUser(username string, password string) (error, string) {
	if c.initErr != nil {
		return c.initErr, ""
	}
	resp, err := c.api.PostApiV1UserLoginWithResponse(context.Background(), nil, generatedapi.UserUserLogin{
		Email:    &username,
		Password: &password,
	})
	if err != nil {
		return err, ""
	}
	if resp == nil || resp.HTTPResponse == nil {
		return fmt.Errorf("login failed: empty response"), ""
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("login failed: status %s", resp.Status()), ""
	}

	for _, cookie := range resp.HTTPResponse.Cookies() {
		if cookie.Name == "session_id" && cookie.Value != "" {
			c.sessionID = cookie.Value
			break
		}
	}
	if c.sessionID == "" {
		return fmt.Errorf("login failed: no session cookie received"), ""
	}
	err, user := c.GetUserInfo()
	if err == nil {
		c.User = user
	}

	return nil, c.sessionID
}

func (c *Client) GetUserInfo() (error, User) {
	if c.initErr != nil {
		return c.initErr, User{}
	}
	resp, err := c.api.GetApiV1UserSelfWithResponse(context.Background())
	if err != nil {
		return err, User{}
	}
	if resp == nil || resp.HTTPResponse == nil || resp.JSON200 == nil {
		return fmt.Errorf("get user failed: empty response"), User{}
	}
	return nil, User{UUID: derefString(resp.JSON200.Uuid)}
}

func (c *Client) GetChats(page int64, limit int64) (error, PaginatedChats) {
	if c.initErr != nil {
		return c.initErr, PaginatedChats{}
	}
	pageInt := int(page)
	limitInt := int(limit)
	resp, err := c.api.GetApiV1ChatsListWithResponse(context.Background(), &generatedapi.GetApiV1ChatsListParams{
		Page:  &pageInt,
		Limit: &limitInt,
	})
	if err != nil {
		return err, PaginatedChats{}
	}
	if resp == nil || resp.HTTPResponse == nil {
		return fmt.Errorf("get chats failed: empty response"), PaginatedChats{}
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("get chats failed: status %s", resp.Status()), PaginatedChats{}
	}
	pageData := PaginatedChats{
		Limit:      derefInt(resp.JSON200.Limit),
		Page:       derefInt(resp.JSON200.Page),
		TotalPages: derefInt(resp.JSON200.TotalPages),
		Rows:       []ListedChat{},
	}
	if resp.JSON200.Rows != nil {
		for _, row := range *resp.JSON200.Rows {
			pageData.Rows = append(pageData.Rows, convertListedChat(row))
		}
	}
	return nil, pageData
}

func (c *Client) GetMetrics() (error, map[string]interface{}) {
	req, err := http.NewRequest(http.MethodGet, c.host+"/api/v1/metrics", nil)
	if err != nil {
		return err, nil
	}
	req.Header.Set("Origin", c.host)
	req.Header.Set("Content-Type", "application/json")
	if c.sessionID != "" {
		req.Header.Set("Cookie", "session_id="+c.sessionID)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("get metrics failed: status %s", resp.Status), nil
	}

	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err, nil
	}
	return nil, out
}

func (c *Client) GetApiKey(keyName string) string {
	return c.apiKeys[keyName]
}

func (c *Client) SendChatMessage(chatUUID string, data SendMessage) error {
	if c.initErr != nil {
		return c.initErr
	}
	body := generatedapi.ChatsSendMessage{
		Text:      &data.Text,
		Reasoning: &data.Reasoning,
		MetaData:  data.MetaData,
		ToolCalls: data.ToolCalls,
	}
	resp, err := c.api.PostApiV1ChatsChatUuidMessagesSendWithResponse(context.Background(), chatUUID, body)
	if err != nil {
		return err
	}
	if resp == nil || resp.HTTPResponse == nil {
		return fmt.Errorf("send message failed: empty response")
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("send message failed: status %s", resp.Status())
	}
	return nil
}

func (c *Client) GetMessages(chatUUID string, page int64, limit int64) (error, PaginatedMessages) {
	if c.initErr != nil {
		return c.initErr, PaginatedMessages{}
	}
	pageInt := int(page)
	limitInt := int(limit)
	resp, err := c.api.GetApiV1ChatsChatUuidMessagesListWithResponse(context.Background(), chatUUID, &generatedapi.GetApiV1ChatsChatUuidMessagesListParams{
		Page:  &pageInt,
		Limit: &limitInt,
	})
	if err != nil {
		return err, PaginatedMessages{}
	}
	if resp == nil || resp.HTTPResponse == nil || resp.JSON200 == nil {
		return fmt.Errorf("get messages failed: empty response"), PaginatedMessages{}
	}
	out := PaginatedMessages{
		Limit:      derefInt(resp.JSON200.Limit),
		Page:       derefInt(resp.JSON200.Page),
		TotalPages: derefInt(resp.JSON200.TotalPages),
		Rows:       []ListedMessage{},
	}
	if resp.JSON200.Rows != nil {
		for _, row := range *resp.JSON200.Rows {
			out.Rows = append(out.Rows, ListedMessage{
				UUID:              derefString(row.Uuid),
				SendAt:            derefString(row.SendAt),
				SenderID:          uint(derefInt(row.SenderId)),
				ReceiverID:        uint(derefInt(row.ReceiverId)),
				SenderUUID:        derefString(row.SenderUuid),
				SenderIsAutomated: derefBool(row.SenderIsAutomated),
				DataType:          derefString(row.DataType),
				Text:              derefString(row.Text),
				Reasoning:         row.Reasoning,
				ToolCalls:         row.ToolCalls,
				MetaData:          row.MetaData,
			})
		}
	}
	return nil, out
}

func (c *Client) GetChat(chatUUID string) (error, ListedChat) {
	if c.initErr != nil {
		return c.initErr, ListedChat{}
	}
	resp, err := c.api.GetApiV1ChatsChatUuidWithResponse(context.Background(), chatUUID)
	if err != nil {
		return err, ListedChat{}
	}
	if resp == nil || resp.HTTPResponse == nil || resp.JSON200 == nil {
		return fmt.Errorf("get chat failed: empty response"), ListedChat{}
	}
	return nil, convertListedChat(*resp.JSON200)
}

func (c *Client) ListContacts(page int64, limit int64) (error, PaginatedContacts) {
	if c.initErr != nil {
		return c.initErr, PaginatedContacts{}
	}
	pageInt := int(page)
	limitInt := int(limit)
	resp, err := c.api.GetApiV1ContactsListWithResponse(context.Background(), &generatedapi.GetApiV1ContactsListParams{
		Page:  &pageInt,
		Limit: &limitInt,
	})
	if err != nil {
		return err, PaginatedContacts{}
	}
	if resp == nil || resp.HTTPResponse == nil || resp.JSON200 == nil {
		return fmt.Errorf("list contacts failed: empty response"), PaginatedContacts{}
	}
	out := PaginatedContacts{
		Limit:      derefInt(resp.JSON200.Limit),
		Page:       derefInt(resp.JSON200.Page),
		TotalPages: derefInt(resp.JSON200.TotalPages),
		Rows:       []ListedContact{},
	}
	if resp.JSON200.Rows != nil {
		for _, row := range *resp.JSON200.Rows {
			contact := ListedContact{
				ContactToken: derefString(row.ContactToken),
				Name:         derefString(row.Name),
				UserUUID:     derefString(row.UserUuid),
				IsOnline:     derefBool(row.IsOnline),
				IsAutomated:  derefBool(row.IsAutomated),
				ProfileData:  map[string]interface{}{},
			}
			if row.ProfileData != nil {
				contact.ProfileData = *row.ProfileData
			}
			out.Rows = append(out.Rows, contact)
		}
	}
	return nil, out
}

func (c *Client) CreateChatWithAttachments(contactToken string, firstMessage string, attachments []FileAttachment, sharedConfig map[string]interface{}, chatType string) (error, ListedChat) {
	createChatData := map[string]interface{}{
		"contact_token": contactToken,
		"first_message": firstMessage,
		"shared_config": sharedConfig,
		"chat_type":     chatType,
		"attachments":   attachments,
	}
	return c.CreateChat(createChatData)
}

func (c *Client) CreateChat(data interface{}) (error, ListedChat) {
	if c.initErr != nil {
		return c.initErr, ListedChat{}
	}
	bodyBytes, err := json.Marshal(data)
	if err != nil {
		return err, ListedChat{}
	}
	resp, err := c.api.PostApiV1ChatsCreateWithBodyWithResponse(context.Background(), "application/json", strings.NewReader(string(bodyBytes)))
	if err != nil {
		return err, ListedChat{}
	}
	if resp == nil || resp.HTTPResponse == nil || resp.JSON200 == nil {
		if resp != nil && len(resp.Body) > 0 {
			return fmt.Errorf("create chat failed: status %s - %s", resp.Status(), strings.TrimSpace(string(resp.Body))), ListedChat{}
		}
		return fmt.Errorf("create chat failed: empty response"), ListedChat{}
	}
	return nil, convertListedChat(*resp.JSON200)
}

func (c *Client) RandomPassword() string {
	const passwordLength = 12
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	password := make([]byte, passwordLength)
	for i := range password {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "password"
		}
		password[i] = charset[num.Int64()]
	}

	return string(password)
}

func (c *Client) RandomSSHPort() string {
	num, err := rand.Int(rand.Reader, big.NewInt(65535-1024))
	if err != nil {
		return "2222"
	}
	return strconv.Itoa(int(num.Int64()) + 1024)
}

func convertListedChat(in generatedapi.ChatsListedChat) ListedChat {
	return ListedChat{
		UUID:          derefString(in.Uuid),
		Partner:       toPlainJSON(in.Partner),
		LatestMessage: toPlainJSON(in.LatestMessage),
		ChatType:      derefString(in.ChatType),
		Config:        toPlainJSON(in.Config),
		ChatShareUUID: derefString(in.ChatShareUuid),
		SharedChatURL: derefString(in.SharedInteractionUrl),
	}
}

func toPlainJSON(in interface{}) interface{} {
	if in == nil {
		return nil
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return in
	}
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return in
	}
	return out
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func derefBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func readBody(resp *http.Response) string {
	if resp == nil || resp.Body == nil {
		return ""
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(body))
}
