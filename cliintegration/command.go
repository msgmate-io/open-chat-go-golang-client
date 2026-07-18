package cliintegration

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
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

	"github.com/msgmate-io/go-client-integration/goclient"
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
}

func GetClientCmd(action string) *cli.Command {
	switch strings.TrimSpace(action) {
	case "login":
		return clientLoginCmd()
	case "auth":
		return clientAuthCmd()
	case "chats":
		return clientChatsCmd()
	case "hash-password":
		return clientHashPasswordCmd()
	default:
		return nil
	}
}

func ClientCli() *cli.Command {
	return &cli.Command{
		Name:  "client",
		Usage: "Open Chat client utilities",
		Commands: []*cli.Command{
			clientAuthCmd(),
			clientLoginCmd(),
			clientChatsCmd(),
			clientHashPasswordCmd(),
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
				Usage: "Maximum wait time for browser auth callback",
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

			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				return fmt.Errorf("failed to start callback listener: %w", err)
			}
			defer ln.Close()

			callbackURL := "http://" + ln.Addr().String() + "/callback"
			authURL := buildBrowserAuthURL(host, callbackURL, state, tokenName)

			tokenCh := make(chan string, 1)
			errCh := make(chan error, 1)
			server := &http.Server{}
			mux := http.NewServeMux()
			var once sync.Once
			mux.HandleFunc("GET /callback", func(w http.ResponseWriter, r *http.Request) {
				query := r.URL.Query()
				if query.Get("state") != state {
					http.Error(w, "Invalid auth state", http.StatusBadRequest)
					once.Do(func() { errCh <- fmt.Errorf("invalid auth state") })
					return
				}
				if rawErr := strings.TrimSpace(query.Get("error")); rawErr != "" {
					http.Error(w, rawErr, http.StatusBadRequest)
					once.Do(func() { errCh <- errors.New(rawErr) })
					return
				}
				token := strings.TrimSpace(query.Get("token"))
				if token == "" {
					http.Error(w, "Missing token", http.StatusBadRequest)
					once.Do(func() { errCh <- fmt.Errorf("missing token in callback") })
					return
				}

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte("<html><body><h2>Open Chat CLI authenticated.</h2><p>You can close this window.</p></body></html>"))
				once.Do(func() { tokenCh <- token })
			})
			server.Handler = mux

			go func() {
				if serveErr := server.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
					once.Do(func() { errCh <- serveErr })
				}
			}()

			fmt.Printf("Opening browser for Open Chat auth: %s\n", authURL)
			if err := openBrowser(authURL); err != nil {
				fmt.Printf("Could not auto-open browser. Open this URL manually:\n%s\n", authURL)
			}

			timeout := c.Duration("timeout")
			if timeout <= 0 {
				timeout = 2 * time.Minute
			}

			select {
			case token := <-tokenCh:
				_ = server.Shutdown(context.Background())
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
			case waitErr := <-errCh:
				_ = server.Shutdown(context.Background())
				return fmt.Errorf("browser auth failed: %w", waitErr)
			case <-time.After(timeout):
				_ = server.Shutdown(context.Background())
				return fmt.Errorf("browser auth timed out after %s", timeout)
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
			host := getHostWithPrecedence(c)
			ocClient := goclient.NewClient(host)

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
				return fmt.Errorf("no API token available, run `open-chat client auth` first")
			}
			ocClient.SetAccessToken(apiToken)

			err, paginatedChats := ocClient.GetChats(int64(c.Int("page")), int64(c.Int("limit")))
			if err != nil {
				return fmt.Errorf("failed to get chats: %w", err)
			}
			pretty, err := json.MarshalIndent(paginatedChats, "", "  ")
			if err != nil {
				return fmt.Errorf("failed to marshal chats: %w", err)
			}
			fmt.Println(string(pretty))
			return nil
		},
	}
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

func buildBrowserAuthURL(host, redirectURI, state, tokenName string) string {
	base := strings.TrimRight(strings.TrimSpace(host), "/")
	v := url.Values{}
	v.Set("redirect_uri", redirectURI)
	v.Set("state", state)
	v.Set("name", tokenName)
	return base + "/api/user/cli-auth?" + v.Encode()
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
