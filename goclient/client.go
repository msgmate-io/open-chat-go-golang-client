package goclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	generatedapi "github.com/msgmate-io/go-client-integration/generated_api"
)

type Client struct {
	host      string
	sessionID string
	api       *generatedapi.ClientWithResponses
	initErr   error
}

func NewClient(host string) *Client {
	normalizedHost := strings.TrimSpace(host)
	normalizedHost = strings.TrimRight(normalizedHost, "/")
	if normalizedHost == "" {
		normalizedHost = "http://localhost:1984"
	}

	client := &Client{host: normalizedHost}
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
	if c.sessionID != "" {
		req.Header.Set("Cookie", fmt.Sprintf("session_id=%s", c.sessionID))
	}
	return nil
}

func (c *Client) SetSessionId(sessionID string) {
	c.sessionID = strings.TrimSpace(sessionID)
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

	return nil, c.sessionID
}

func (c *Client) GetChats(page int64, limit int64) (error, generatedapi.ChatsListedChatsPage) {
	if c.initErr != nil {
		return c.initErr, generatedapi.ChatsListedChatsPage{}
	}
	pageInt := int(page)
	limitInt := int(limit)
	resp, err := c.api.GetApiV1ChatsListWithResponse(context.Background(), &generatedapi.GetApiV1ChatsListParams{
		Page:  &pageInt,
		Limit: &limitInt,
	})
	if err != nil {
		return err, generatedapi.ChatsListedChatsPage{}
	}
	if resp == nil || resp.HTTPResponse == nil {
		return fmt.Errorf("get chats failed: empty response"), generatedapi.ChatsListedChatsPage{}
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("get chats failed: status %s", resp.Status()), generatedapi.ChatsListedChatsPage{}
	}
	return nil, *resp.JSON200
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
