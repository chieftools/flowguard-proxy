//go:build devtools

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"flowguard/config"
	"flowguard/middleware"

	"github.com/spf13/cobra"
)

var (
	devPreviewListen     string
	devPreviewDifficulty int
	devPreviewWorkUnits  int
	devPreviewMinPageMs  int
)

var devPreviewCmd = &cobra.Command{
	Use:   "dev",
	Short: "Run a local challenge/rule preview server",
	Long: `Run a local-only FlowGuard preview server with a built-in demo backend.

This command does not install firewall rules, does not require certificates, and
does not proxy to any external service. It is intended for previewing rendered
FlowGuard pages and rule behavior during development.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runDevPreview(cmd.Context())
	},
}

func init() {
	rootCmd.AddCommand(devPreviewCmd)

	devPreviewCmd.Flags().StringVar(&devPreviewListen, "listen", "127.0.0.1:18080", "Address for the preview proxy to listen on")
	devPreviewCmd.Flags().IntVar(&devPreviewDifficulty, "difficulty", 18, "Proof-of-work difficulty bits; calibrated mode derives work units from this when --work-units=0")
	devPreviewCmd.Flags().IntVar(&devPreviewWorkUnits, "work-units", 0, "Calibrated proof-of-work units for the preview challenge; 0 derives from difficulty")
	devPreviewCmd.Flags().IntVar(&devPreviewMinPageMs, "min-page-time-ms", 1500, "Minimum time the preview challenge page must be shown before continuing")
}

func runDevPreview(ctx context.Context) error {
	tempDir, err := os.MkdirTemp("", "flowguard-dev-preview-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	configPath := filepath.Join(tempDir, "config.json")
	if err := writeDevPreviewConfig(configPath, devPreviewDifficulty); err != nil {
		return err
	}

	configMgr, err := config.NewManager(configPath, GetUserAgent(), GetVersion(), filepath.Join(tempDir, "cache"), verbose)
	if err != nil {
		return fmt.Errorf("load preview config: %w", err)
	}
	defer configMgr.Stop()

	backendListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen for preview backend: %w", err)
	}
	backendURL := &url.URL{Scheme: "http", Host: backendListener.Addr().String()}
	backendServer := &http.Server{
		Handler:           devPreviewBackendHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		if err := backendServer.Serve(backendListener); err != nil && err != http.ErrServerClosed {
			log.Printf("[dev-preview] Backend server stopped: %v", err)
		}
	}()
	defer shutdownHTTPServer(backendServer)

	chain := middleware.NewChain()
	chain.Add(middleware.NewTimingMiddleware())
	rulesMiddleware := middleware.NewRulesMiddleware(configMgr)
	chain.Add(rulesMiddleware)
	defer chain.Stop()

	proxy := httputil.NewSingleHostReverseProxy(backendURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		http.Error(w, "Preview backend unavailable", http.StatusBadGateway)
	}

	previewServer := &http.Server{
		Addr:              devPreviewListen,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chain.ServeHTTPWithHandler(w, r, proxy)
		}),
	}

	errChan := make(chan error, 1)
	go func() {
		if err := previewServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	log.Printf("[dev-preview] Backend listening at %s", backendURL.String())
	log.Printf("[dev-preview] Preview available at http://%s", devPreviewListen)
	log.Printf("[dev-preview] Open http://%s/ for links to challenge, block, and rate-limit scenarios", devPreviewListen)
	log.Printf("[dev-preview] Press Ctrl+C to stop")

	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-signalCtx.Done():
		return shutdownHTTPServer(previewServer)
	case err := <-errChan:
		shutdownHTTPServer(previewServer)
		return fmt.Errorf("preview server stopped: %w", err)
	}
}

func writeDevPreviewConfig(path string, difficulty int) error {
	if difficulty < 1 || difficulty > 30 {
		return fmt.Errorf("difficulty must be between 1 and 30")
	}
	if devPreviewWorkUnits < 0 || devPreviewWorkUnits > 100000 {
		return fmt.Errorf("work-units must be 0 or between 1 and 100000")
	}
	if devPreviewMinPageMs < 0 || devPreviewMinPageMs > 60000 {
		return fmt.Errorf("min-page-time-ms must be between 0 and 60000")
	}

	cfg := config.Config{
		Host: &config.HostConfig{
			Key:  "dev-preview-secret",
			Name: "FlowGuard Dev Preview",
		},
		Challenges: &config.ChallengesConfig{
			DefaultTTLSeconds:    devPreviewIntPtr(1800),
			MinPageTimeMs:        devPreviewIntPtr(devPreviewMinPageMs),
			MaxAttemptsPerWindow: devPreviewIntPtr(20),
			AttemptWindowSeconds: devPreviewIntPtr(60),
			PoW: &config.PoWChallengeConfig{
				ChallengeTTLSeconds: devPreviewIntPtr(120),
				DifficultyBits:      difficulty,
				Algorithm:           config.PoWAlgorithmPBKDF2SHA256,
				PBKDF2Iterations:    100,
				EffortMode:          config.PoWEffortModeCalibrated,
				WorkUnits:           devPreviewWorkUnits,
			},
		},
		Rules: map[string]*config.Rule{
			"challenge-page": {
				Action:    "challenge-pow",
				SortOrder: devPreviewIntPtr(10),
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{Type: "path", Match: "starts-with", Value: "/challenge"},
					},
				},
			},
			"block-page": {
				Action:    "block-403",
				SortOrder: devPreviewIntPtr(20),
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{Type: "path", Match: "starts-with", Value: "/blocked"},
					},
				},
			},
			"rate-limit-page": {
				Action:    "rate-limit-preview",
				SortOrder: devPreviewIntPtr(30),
				Conditions: &config.RuleConditions{
					Matches: []config.MatchCondition{
						{Type: "path", Match: "starts-with", Value: "/rate-limit"},
					},
				},
			},
		},
		Actions: map[string]*config.RuleAction{
			"challenge-pow": {
				Action:  "challenge",
				Message: "Security check required",
				Challenge: &config.RuleActionChallengeConfig{
					Type:             config.ChallengeTypePoW,
					ClearanceScope:   config.ChallengeScopeRule,
					TTLSeconds:       devPreviewIntPtr(1800),
					MinPageTimeMs:    devPreviewIntPtr(devPreviewMinPageMs),
					DifficultyBits:   difficulty,
					Algorithm:        config.PoWAlgorithmPBKDF2SHA256,
					PBKDF2Iterations: 100,
					EffortMode:       config.PoWEffortModeCalibrated,
					WorkUnits:        devPreviewWorkUnits,
				},
			},
			"block-403": {
				Action:  "block",
				Status:  http.StatusForbidden,
				Message: "Preview block page",
			},
			"rate-limit-preview": {
				Action:            "rate_limit",
				Status:            http.StatusTooManyRequests,
				Message:           "Preview rate limit exceeded",
				RequestsPerWindow: 3,
				WindowSeconds:     15,
			},
		},
	}

	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal preview config: %w", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return fmt.Errorf("write preview config: %w", err)
	}
	return nil
}

func devPreviewBackendHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>FlowGuard Dev Preview</title>
  <style>
    body { color: #111827; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 40px; max-width: 720px; }
    h1 { font-size: 28px; margin-bottom: 8px; }
    p { color: #4b5563; line-height: 1.5; }
    ul { line-height: 1.9; padding-left: 22px; }
    code { background: #f3f4f6; border-radius: 4px; padding: 2px 5px; }
  </style>
</head>
<body>
  <h1>FlowGuard Dev Preview</h1>
  <p>This backend page is served through the local FlowGuard preview middleware.</p>
  <ul>
    <li><a href="/challenge">Challenge interstitial</a> - first visit should show the proof-of-work page, then redirect back here with clearance.</li>
    <li><a href="/blocked">Block page</a> - shows the FlowGuard blocked HTML page.</li>
    <li><a href="/rate-limit">Rate limit page</a> - refresh more than three times within 15 seconds to see the rate limit page.</li>
    <li><a href="/plain">Plain backend page</a> - no rule should fire.</li>
  </ul>
  <p>FlowGuard internal routes are reserved under <code>/fg-cgi/</code>.</p>
</body>
</html>`)
	})
	mux.HandleFunc("/challenge", func(w http.ResponseWriter, r *http.Request) {
		writePreviewScenarioPage(w, "Challenge passed", "The clearance cookie is valid for this rule. Clearing cookies will show the challenge again.")
	})
	mux.HandleFunc("/rate-limit", func(w http.ResponseWriter, r *http.Request) {
		writePreviewScenarioPage(w, "Rate limit backend response", "Refresh this page repeatedly to trigger the configured rate limit.")
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		writePreviewScenarioPage(w, "Plain backend response", "No FlowGuard preview rule matched this page.")
	})
	return mux
}

func writePreviewScenarioPage(w http.ResponseWriter, title string, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>%s | FlowGuard Dev Preview</title>
  <style>
    body { color: #111827; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif; margin: 40px; max-width: 720px; }
    a { color: #047857; }
    p { color: #4b5563; line-height: 1.5; }
  </style>
</head>
<body>
  <h1>%s</h1>
  <p>%s</p>
  <p><a href="/">Back to scenarios</a></p>
</body>
</html>`, title, title, message)
}

func shutdownHTTPServer(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return server.Shutdown(ctx)
}

func devPreviewIntPtr(v int) *int {
	return &v
}
