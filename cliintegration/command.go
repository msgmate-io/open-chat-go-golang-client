package cliintegration

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/msgmate-io/open-chat-go-golang-client/goclient"
	"github.com/urfave/cli/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

type storedAuthConfig struct {
	Host        string `json:"host"`
	AccessToken string `json:"access_token"`
	UpdatedAt   string `json:"updated_at"`
}

var defaultFlags = []cli.Flag{
	&cli.StringFlag{
		Name:    "host",
		Usage:   "The host to connect to",
		Value:   "http://localhost:1984",
		Sources: cli.EnvVars("OPEN_CHAT_HOST"),
	},
	&cli.StringFlag{
		Name:    "api-token",
		Usage:   "Bearer API token to use for auth",
		Value:   "",
		Sources: cli.EnvVars("OPEN_CHAT_API_TOKEN"),
	},
	&cli.BoolFlag{
		Name:  "json",
		Usage: "Print raw JSON response",
		Value: false,
	},
}

var (
	clientCommandRegistryMu sync.RWMutex
	clientCommandRegistry   = map[string]*cli.Command{}
)

func RegisterClientCommand(cmd *cli.Command) error {
	if cmd == nil {
		return fmt.Errorf("client command is required")
	}
	name := strings.TrimSpace(cmd.Name)
	if name == "" {
		return fmt.Errorf("client command name is required")
	}
	clientCommandRegistryMu.Lock()
	defer clientCommandRegistryMu.Unlock()
	if _, exists := clientCommandRegistry[name]; exists {
		return fmt.Errorf("client command %q already registered", name)
	}
	clientCommandRegistry[name] = cmd
	return nil
}

func MustRegisterClientCommand(cmd *cli.Command) {
	if err := RegisterClientCommand(cmd); err != nil {
		panic(err)
	}
}

func registeredClientCommands() []*cli.Command {
	clientCommandRegistryMu.RLock()
	defer clientCommandRegistryMu.RUnlock()
	out := make([]*cli.Command, 0, len(clientCommandRegistry))
	for _, cmd := range clientCommandRegistry {
		out = append(out, cmd)
	}
	return out
}

func GetClientCmd(action string) *cli.Command {
	switch strings.TrimSpace(action) {
	case "login":
		return clientLoginCmd()
	case "auth":
		return clientAuthCmd()
	case "get":
		return clientGetCmd()
	case "chats":
		return clientChatsCmd()
	case "hash-password":
		return clientHashPasswordCmd()
	default:
		return nil
	}
}

func ClientCli() *cli.Command {
	commands := []*cli.Command{
		clientAuthCmd(),
		clientLoginCmd(),
		clientGetCmd(),
		clientChatsCmd(),
		clientHashPasswordCmd(),
	}
	commands = append(commands, registeredClientCommands()...)
	return &cli.Command{
		Name:     "client",
		Usage:    "Open Chat client utilities",
		Commands: commands,
	}
}

func ResolveHostAndAPIToken(c *cli.Command) (string, string, error) {
	host := getHostWithPrecedence(c)
	apiToken := strings.TrimSpace(c.String("api-token"))
	if apiToken == "" {
		stored, err := loadStoredAuthConfig()
		if err == nil {
			if stored.AccessToken != "" && sameHost(stored.Host, host) {
				apiToken = stored.AccessToken
			}
		}
	}
	if apiToken == "" {
		return host, "", fmt.Errorf("no API token available, run `open-chat client auth` first")
	}
	return host, apiToken, nil
}

func ResolveAuthenticatedClient(c *cli.Command) (*goclient.Client, string, error) {
	host, apiToken, err := ResolveHostAndAPIToken(c)
	if err != nil {
		return nil, "", err
	}
	ocClient := goclient.NewClient(host)
	ocClient.SetAccessToken(apiToken)
	return ocClient, host, nil
}

func ClientAuthFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "host",
			Usage:   "The host to connect to",
			Value:   "http://localhost:1984",
			Sources: cli.EnvVars("OPEN_CHAT_HOST"),
		},
		&cli.StringFlag{
			Name:    "api-token",
			Usage:   "Bearer API token to use for auth",
			Value:   "",
			Sources: cli.EnvVars("OPEN_CHAT_API_TOKEN"),
		},
	}
}

func clientAuthCmd() *cli.Command {
	return &cli.Command{
		Name:  "auth",
		Usage: "Authenticate via browser and store API token",
		Flags: append(defaultFlags, []cli.Flag{
			&cli.StringFlag{
				Name:  "token-name",
				Usage: "Display name for generated access token",
				Value: "open-chat-cli",
			},
			&cli.DurationFlag{
				Name:  "timeout",
				Usage: "Maximum wait time for browser auth completion",
				Value: 2 * time.Minute,
			},
		}...),
		Action: func(_ context.Context, c *cli.Command) error {
			host := getHostWithPrecedence(c)
			tokenName := strings.TrimSpace(c.String("token-name"))
			if tokenName == "" {
				tokenName = "open-chat-cli"
			}

			state, err := randomHex(24)
			if err != nil {
				return fmt.Errorf("failed to create auth state: %w", err)
			}

			authURL := buildBrowserAuthURL(host, state, tokenName)

			fmt.Printf("Opening browser for Open Chat auth: %s\n", authURL)
			if err := openBrowser(authURL); err != nil {
				fmt.Printf("Could not auto-open browser. Open this URL manually:\n%s\n", authURL)
			}

			timeout := c.Duration("timeout")
			if timeout <= 0 {
				timeout = 2 * time.Minute
			}

			deadline := time.Now().Add(timeout)
			for {
				if time.Now().After(deadline) {
					return fmt.Errorf("browser auth timed out after %s", timeout)
				}

				token, ready, pollErr := pollForBrowserAuthResult(host, state)
				if pollErr != nil {
					return pollErr
				}
				if ready {
					verificationClient := goclient.NewClient(host)
					verificationClient.SetAccessToken(token)
					if verifyErr, _ := verificationClient.GetUserInfo(); verifyErr != nil {
						return fmt.Errorf("received token is invalid: %w", verifyErr)
					}
					if err := saveStoredAuthConfig(storedAuthConfig{
						Host:        host,
						AccessToken: token,
						UpdatedAt:   time.Now().UTC().Format(time.RFC3339),
					}); err != nil {
						return fmt.Errorf("failed to persist token config: %w", err)
					}
					fmt.Println("Client auth successful. Token saved to local config.")
					return nil
				}

				time.Sleep(2 * time.Second)
			}
		},
	}
}

func clientLoginCmd() *cli.Command {
	return &cli.Command{
		Name:  "login",
		Usage: "Login to the client",
		Flags: append(defaultFlags, []cli.Flag{
			&cli.StringFlag{
				Name:    "username",
				Usage:   "The username to use",
				Sources: cli.EnvVars("OPEN_CHAT_USERNAME"),
				Value:   "",
			},
			&cli.StringFlag{
				Name:  "password",
				Usage: "The password to use",
				Value: "",
			},
		}...),
		Action: func(_ context.Context, c *cli.Command) error {
			host := getHostWithPrecedence(c)
			ocClient := goclient.NewClient(host)

			username := c.String("username")
			password := c.String("password")

			var err error
			if username == "" && password == "" {
				username, password, err = promptForUsernameAndPassword()
				if err != nil {
					return fmt.Errorf("failed to get username and password: %w", err)
				}
			} else if username != "" && password == "" {
				fmt.Println("Using username:", username, "please enter password")
				password, err = promptForPassword()
				if err != nil {
					return fmt.Errorf("failed to get password: %w", err)
				}
			}

			err, sessionID := ocClient.LoginUser(username, password)
			if err != nil {
				return fmt.Errorf("failed to login: %w", err)
			}

			env := os.Environ()
			env = append(env, fmt.Sprintf("OPEN_CHAT_SESSION_ID=%s", sessionID))
			env = append(env, fmt.Sprintf("OPEN_CHAT_HOST=%s", host))
			env = append(env, fmt.Sprintf("OPEN_CHAT_USERNAME=%s", username))
			env = append(env, fmt.Sprintf("OPEN_CHAT_SEAL_KEY=%s", password))

			shell := os.Getenv("SHELL")
			if shell == "" {
				shell = "/bin/sh"
			}
			proc, err := os.StartProcess(shell, []string{shell}, &os.ProcAttr{
				Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
				Env:   env,
			})
			if err != nil {
				return fmt.Errorf("failed to start shell: %w", err)
			}

			_, err = proc.Wait()
			if err != nil {
				return fmt.Errorf("shell exited with error: %w", err)
			}
			return nil
		},
	}
}

func clientChatsCmd() *cli.Command {
	return &cli.Command{
		Name:  "chats",
		Usage: "List all chats",
		Flags: append(defaultFlags, []cli.Flag{
			&cli.IntFlag{Name: "page", Usage: "The page number to return", Value: 1},
			&cli.IntFlag{Name: "limit", Usage: "The number of chats to return", Value: 20},
		}...),
		Action: func(_ context.Context, c *cli.Command) error {
			ocClient, _, err := ResolveAuthenticatedClient(c)
			if err != nil {
				return err
			}

			err, paginatedChats := ocClient.GetChats(int64(c.Int("page")), int64(c.Int("limit")))
			if err != nil {
				return fmt.Errorf("failed to get chats: %w", err)
			}
			return printAPIResponse(paginatedChats, c.Bool("json"), goclient.FormatPaginatedChatsReadable)
		},
	}
}

func clientGetCmd() *cli.Command {
	return &cli.Command{
		Name:  "get",
		Usage: "Get resources (kubectl-style)",
		Commands: []*cli.Command{
			{
				Name:      "chat",
				Usage:     "Get one chat by UUID",
				ArgsUsage: "<chat-uuid>",
				Flags:     append(defaultFlags, []cli.Flag{}...),
				Action: func(_ context.Context, c *cli.Command) error {
					chatUUID, err := requireSingleArg(c, "chat-uuid")
					if err != nil {
						return err
					}

					ocClient, _, err := ResolveAuthenticatedClient(c)
					if err != nil {
						return err
					}

					err, chat := ocClient.GetChat(chatUUID)
					if err != nil {
						return fmt.Errorf("failed to get chat: %w", err)
					}
					return printAPIResponse(chat, c.Bool("json"), goclient.FormatListedChatReadable)
				},
			},
			{
				Name:      "messages",
				Usage:     "Get messages for a chat UUID",
				ArgsUsage: "<chat-uuid>",
				Flags: append(defaultFlags, []cli.Flag{
					&cli.IntFlag{Name: "page", Usage: "The page number to return", Value: 1},
					&cli.IntFlag{Name: "limit", Usage: "The number of messages to return", Value: 20},
				}...),
				Action: func(_ context.Context, c *cli.Command) error {
					chatUUID, err := requireSingleArg(c, "chat-uuid")
					if err != nil {
						return err
					}

					ocClient, _, err := ResolveAuthenticatedClient(c)
					if err != nil {
						return err
					}

					err, paginatedMessages := ocClient.GetMessages(chatUUID, int64(c.Int("page")), int64(c.Int("limit")))
					if err != nil {
						return fmt.Errorf("failed to get messages: %w", err)
					}
					return printAPIResponse(paginatedMessages, c.Bool("json"), goclient.FormatPaginatedMessagesReadable)
				},
			},
		},
	}
}

func requireSingleArg(c *cli.Command, argName string) (string, error) {
	if c.Args().Len() != 1 {
		return "", fmt.Errorf("expected exactly one argument: <%s>", argName)
	}
	value := strings.TrimSpace(c.Args().First())
	if value == "" {
		return "", fmt.Errorf("argument <%s> cannot be empty", argName)
	}
	return value, nil
}

func printAPIResponse[T any](value T, asJSON bool, readableFormatter func(T) (string, error)) error {
	if !asJSON && readableFormatter != nil {
		readable, err := readableFormatter(value)
		if err != nil {
			return err
		}
		fmt.Println(readable)
		return nil
	}

	pretty, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON response: %w", err)
	}
	fmt.Println(string(pretty))
	return nil
}

func sameHost(a, b string) bool {
	normalize := func(v string) string {
		return strings.TrimRight(strings.ToLower(strings.TrimSpace(v)), "/")
	}
	return normalize(a) == normalize(b)
}

func clientHashPasswordCmd() *cli.Command {
	return &cli.Command{
		Name:  "hash-password",
		Usage: "Hash a password",
		Flags: append(defaultFlags, []cli.Flag{
			&cli.StringFlag{Name: "password", Usage: "The password to hash", Value: ""},
		}...),
		Action: func(_ context.Context, c *cli.Command) error {
			hashed, err := bcrypt.GenerateFromPassword([]byte(c.String("password")), bcrypt.DefaultCost)
			if err != nil {
				return fmt.Errorf("failed to hash password: %w", err)
			}
			fmt.Println("Hashed password:", string(hashed))
			return nil
		},
	}
}

func getHostWithPrecedence(c *cli.Command) string {
	if c != nil && c.IsSet("host") {
		return strings.TrimRight(strings.TrimSpace(c.String("host")), "/")
	}
	if envHost := strings.TrimSpace(os.Getenv("OPEN_CHAT_HOST")); envHost != "" {
		return strings.TrimRight(envHost, "/")
	}
	if stored, err := loadStoredAuthConfig(); err == nil && strings.TrimSpace(stored.Host) != "" {
		return strings.TrimRight(strings.TrimSpace(stored.Host), "/")
	}
	return "http://localhost:1984"
}

func buildBrowserAuthURL(host, state, tokenName string) string {
	base := strings.TrimRight(strings.TrimSpace(host), "/")
	v := url.Values{}
	v.Set("state", state)
	v.Set("name", tokenName)
	return base + "/api/user/cli-auth?" + v.Encode()
}

func pollForBrowserAuthResult(host, state string) (token string, ready bool, err error) {
	base := strings.TrimRight(strings.TrimSpace(host), "/")
	pollURL := base + "/api/user/cli-auth/poll?state=" + url.QueryEscape(state)

	resp, reqErr := http.Get(pollURL)
	if reqErr != nil {
		return "", false, fmt.Errorf("failed to poll browser auth: %w", reqErr)
	}
	defer resp.Body.Close()

	var payload struct {
		Ready bool   `json:"ready"`
		Token string `json:"token"`
		Error string `json:"error"`
	}
	if decodeErr := json.NewDecoder(resp.Body).Decode(&payload); decodeErr != nil {
		return "", false, fmt.Errorf("failed to decode auth poll response: %w", decodeErr)
	}

	if payload.Error != "" {
		return "", false, fmt.Errorf("browser auth failed: %s", payload.Error)
	}
	if !payload.Ready {
		return "", false, nil
	}
	if strings.TrimSpace(payload.Token) == "" {
		return "", false, fmt.Errorf("browser auth completed without token")
	}

	return strings.TrimSpace(payload.Token), true, nil
}

func randomHex(byteLen int) (string, error) {
	buf := make([]byte, byteLen)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func openBrowser(targetURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", targetURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", targetURL)
	default:
		cmd = exec.Command("xdg-open", targetURL)
	}
	return cmd.Start()
}

func authConfigPath() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "open-chat-go", "client_auth.json"), nil
}

func loadStoredAuthConfig() (storedAuthConfig, error) {
	path, err := authConfigPath()
	if err != nil {
		return storedAuthConfig{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return storedAuthConfig{}, err
	}
	var out storedAuthConfig
	if err := json.Unmarshal(raw, &out); err != nil {
		return storedAuthConfig{}, err
	}
	return out, nil
}

func saveStoredAuthConfig(cfg storedAuthConfig) error {
	path, err := authConfigPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

func promptForUsernameAndPassword() (string, string, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return "", "", fmt.Errorf("failed to read username: %w", err)
	}
	username = strings.TrimSpace(username)

	fmt.Print("Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", "", fmt.Errorf("failed to read password: %w", err)
	}
	password := string(bytePassword)
	fmt.Println()

	return username, password, nil
}

func promptForPassword() (string, error) {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}
	return string(bytePassword), nil
}
