package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"flowguard/config"
)

type challengeMockConfigProvider struct {
	cfg     *config.Config
	rules   map[string]*config.Rule
	actions map[string]*config.RuleAction
}

func (m *challengeMockConfigProvider) GetConfig() *config.Config {
	return m.cfg
}

func (m *challengeMockConfigProvider) GetRules() map[string]*config.Rule {
	return m.rules
}

func (m *challengeMockConfigProvider) GetSortedRules() []*config.Rule {
	if len(m.rules) == 0 {
		return nil
	}

	rules := make([]*config.Rule, 0, len(m.rules))
	for _, rule := range m.rules {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		iHasOrder := rules[i].SortOrder != 0
		jHasOrder := rules[j].SortOrder != 0
		switch {
		case iHasOrder && !jHasOrder:
			return true
		case !iHasOrder && jHasOrder:
			return false
		case iHasOrder && jHasOrder && rules[i].SortOrder != rules[j].SortOrder:
			return rules[i].SortOrder < rules[j].SortOrder
		default:
			return rules[i].ID < rules[j].ID
		}
	})
	return rules
}

func (m *challengeMockConfigProvider) GetActions() map[string]*config.RuleAction {
	return m.actions
}

func TestChallengeManagerIssuesPerRuleClearance(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	manager := NewChallengeManager(provider)
	defer manager.Stop()

	rule := &config.Rule{ID: "admin-rule", Name: "Admin rule"}
	action := &config.RuleAction{
		ID:     "pow-action",
		Name:   "PoW action",
		Action: "challenge",
		Challenge: &config.RuleActionChallengeConfig{
			DifficultyBits: 1,
		},
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "test-browser")

	settings := manager.settings(action)
	token, err := manager.newChallengeToken(req, rule, action, settings)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	nonce, proof := solveChallengeProof(t, token, settings)

	form := url.Values{}
	form.Set("token", token)
	form.Set("nonce", nonce)
	form.Set("proof", proof)
	verifyReq := httptest.NewRequest(http.MethodPost, "https://example.com/fg-cgi/challenge/verify", strings.NewReader(form.Encode()))
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.Header.Set("User-Agent", "test-browser")
	verifyResp := httptest.NewRecorder()

	manager.handleChallengeVerify(verifyResp, verifyReq)

	if verifyResp.Code != http.StatusSeeOther {
		t.Fatalf("expected verify redirect, got %d body %q", verifyResp.Code, verifyResp.Body.String())
	}
	assertChallengeInfo(t, verifyReq, "verify_success", "", "admin-rule", "pow-action")
	assertChallengeInfoNames(t, verifyReq, "Admin rule", "PoW action")
	if got := verifyResp.Header().Get("Location"); got != "/admin" {
		t.Fatalf("expected redirect to /admin, got %q", got)
	}

	cookies := verifyResp.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one clearance cookie, got %d", len(cookies))
	}

	clearedReq := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	clearedReq.Host = "example.com"
	clearedReq.Header.Set("User-Agent", "test-browser")
	clearedReq.AddCookie(cookies[0])
	if !manager.HasValidClearance(clearedReq, rule, action) {
		t.Fatal("expected clearance to pass matching rule")
	}

	otherRule := &config.Rule{ID: "other-rule"}
	if manager.HasValidClearance(clearedReq, otherRule, action) {
		t.Fatal("expected per-rule clearance to reject a different rule")
	}

	replayResp := httptest.NewRecorder()
	manager.handleChallengeVerify(replayResp, verifyReq)
	if replayResp.Code != http.StatusForbidden {
		t.Fatalf("expected replay to be forbidden, got %d", replayResp.Code)
	}
	assertChallengeInfo(t, verifyReq, "verify_failed", "replayed", "admin-rule", "pow-action")
	assertChallengeInfoNames(t, verifyReq, "Admin rule", "PoW action")
}

func TestRulesMiddlewareChallengeHTMLInterstitial(t *testing.T) {
	rules, actions := challengeRulesAndActions()
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	handlerCalled := false
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	resp := httptest.NewRecorder()

	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	if handlerCalled {
		t.Fatal("expected challenge to stop proxy handler")
	}
	if resp.Code != http.StatusForbidden {
		t.Fatalf("expected 403 challenge page, got %d", resp.Code)
	}
	if got := resp.Header().Get("X-FlowGuard-Action"); got != "challenge" {
		t.Fatalf("expected challenge header, got %q", got)
	}
	if !strings.Contains(resp.Body.String(), "Checking your browser") {
		t.Fatal("expected challenge page body")
	}
	if got := GetRuleResult(req); got != "block" {
		t.Fatalf("expected challenge interstitial rule result block, got %q", got)
	}
	assertChallengeInfo(t, req, "issued_html", "missing_proof", "challenge-admin", "challenge-action")
	assertChallengeInfoNames(t, req, "Challenge admin", "Challenge action")
}

func TestChallengeHTMLIncludesNonWebCryptoFallback(t *testing.T) {
	for _, expected := range []string{"sha256Fallback", "hmacSHA256Fallback", "pbkdf2Fallback"} {
		if !strings.Contains(challengeHTML, expected) {
			t.Fatalf("expected challenge page to include %s", expected)
		}
	}
}

func TestRulesMiddlewareChallengeNonHTMLFailsClosed(t *testing.T) {
	rules, actions := challengeRulesAndActions()
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	handlerCalled := false
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "application/json")
	resp := httptest.NewRecorder()

	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	if handlerCalled {
		t.Fatal("expected challenge to stop proxy handler")
	}
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202 fail-closed response, got %d", resp.Code)
	}
	if got := resp.Header().Get("X-FlowGuard-Challenge-URL"); !strings.HasPrefix(got, challengePath+"?token=") {
		t.Fatalf("expected challenge URL header, got %q", got)
	}
	if !strings.Contains(resp.Body.String(), `"Challenge required"`) {
		t.Fatal("expected problem JSON response")
	}
	if got := GetRuleResult(req); got != "block" {
		t.Fatalf("expected non-HTML challenge rule result block, got %q", got)
	}
	assertChallengeInfo(t, req, "issued_non_html", "missing_proof", "challenge-admin", "challenge-action")
	assertChallengeInfoNames(t, req, "Challenge admin", "Challenge action")
}

func TestRulesMiddlewarePreservesClearanceCookieBeforeProxy(t *testing.T) {
	rules, actions := challengeRulesAndActions()
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	cookie := issueChallengeCookie(t, rm.challenges, rules["challenge-admin"], actions["challenge-action"])
	rules["challenge-admin"].Name = "Renamed challenge rule"
	actions["challenge-action"].Name = "Renamed challenge action"
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "test-browser")
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()

	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clearance, err := r.Cookie(cookie.Name)
		if err != nil || clearance.Value != cookie.Value {
			t.Fatalf("expected clearance cookie %q to remain, got %#v err %v", cookie.Name, clearance, err)
		}
		session, err := r.Cookie("session")
		if err != nil || session.Value != "abc" {
			t.Fatalf("expected unrelated session cookie to remain, got %#v err %v", session, err)
		}
		w.WriteHeader(http.StatusOK)
	}))

	if resp.Code != http.StatusOK {
		t.Fatalf("expected cleared request to proxy, got %d", resp.Code)
	}
	if got := GetRuleResult(req); got != "proxy" {
		t.Fatalf("expected cleared challenge rule result proxy, got %q", got)
	}
	assertChallengeInfo(t, req, "passed", "", "challenge-admin", "challenge-action")
	assertChallengeInfoNames(t, req, "Challenge admin", "Challenge action")
}

func TestRulesMiddlewareChallengeWildcardAcceptFailsClosed(t *testing.T) {
	rules, actions := challengeRulesAndActions()
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	handlerCalled := false
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "*/*")
	resp := httptest.NewRecorder()

	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	if handlerCalled {
		t.Fatal("expected challenge to stop proxy handler")
	}
	if resp.Code != http.StatusAccepted {
		t.Fatalf("expected 202 fail-closed response, got %d", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("expected problem JSON content type, got %q", got)
	}
	if !strings.Contains(resp.Body.String(), `"Challenge required"`) {
		t.Fatal("expected problem JSON response")
	}
}

func TestRulesMiddlewareReservesFlowGuardCGI(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	handlerCalled := false
	req := httptest.NewRequest(http.MethodGet, "https://example.com/fg-cgi/missing", nil)
	req.Host = "example.com"
	resp := httptest.NewRecorder()

	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
	}))

	if handlerCalled {
		t.Fatal("expected /fg-cgi/* to be reserved")
	}
	if resp.Code != http.StatusNotFound {
		t.Fatalf("expected FlowGuard 404, got %d", resp.Code)
	}
}

func TestChallengeSettingsUsesNestedPoWConfig(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	provider.cfg.Challenges.PoW = &config.PoWChallengeConfig{
		ChallengeTTLSeconds: testIntPtr(30),
		DifficultyBits:      4,
		Algorithm:           config.PoWAlgorithmSHA256,
		PBKDF2Iterations:    7,
		EffortMode:          config.PoWEffortModeProbabilistic,
		WorkUnits:           9,
	}

	manager := NewChallengeManager(provider)
	defer manager.Stop()

	settings := manager.settings(nil)
	if got := int(settings.ChallengeTTL.Seconds()); got != 30 {
		t.Fatalf("expected nested PoW challenge TTL to win, got %d", got)
	}
	if settings.DifficultyBits != 4 {
		t.Fatalf("expected nested PoW difficulty to win, got %d", settings.DifficultyBits)
	}
	if settings.Algorithm != config.PoWAlgorithmSHA256 {
		t.Fatalf("expected nested PoW algorithm to win, got %q", settings.Algorithm)
	}
	if settings.PBKDF2Iterations != 7 {
		t.Fatalf("expected nested PoW iterations to win, got %d", settings.PBKDF2Iterations)
	}
	if settings.EffortMode != config.PoWEffortModeProbabilistic {
		t.Fatalf("expected nested PoW effort mode to win, got %q", settings.EffortMode)
	}
	if settings.WorkUnits != 9 {
		t.Fatalf("expected nested PoW work units to win, got %d", settings.WorkUnits)
	}
}

func TestChallengeSettingsDefaultCalibratedEffortMatchesDifficulty18(t *testing.T) {
	provider := &challengeMockConfigProvider{
		cfg: &config.Config{
			Host: &config.HostConfig{Key: "test-secret"},
		},
	}

	manager := NewChallengeManager(provider)
	defer manager.Stop()

	settings := manager.settings(nil)
	if settings.DifficultyBits != 18 {
		t.Fatalf("expected default difficulty 18, got %d", settings.DifficultyBits)
	}
	if settings.WorkUnits != 8192 {
		t.Fatalf("expected default calibrated work units 8192, got %d", settings.WorkUnits)
	}
	if got := settings.MinPageTime / time.Millisecond; got != 1500 {
		t.Fatalf("expected default minimum page time 1500ms, got %dms", got)
	}
}

func TestChallengeSettingsDerivesCalibratedWorkUnitsFromDifficulty(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	provider.cfg.Challenges.PoW = &config.PoWChallengeConfig{
		DifficultyBits:   30,
		PBKDF2Iterations: 1,
		EffortMode:       config.PoWEffortModeCalibrated,
	}

	manager := NewChallengeManager(provider)
	defer manager.Stop()

	settings := manager.settings(nil)
	if settings.WorkUnits != 100000 {
		t.Fatalf("expected calibrated work units to derive from difficulty and clamp, got %d", settings.WorkUnits)
	}

	action := &config.RuleAction{
		Challenge: &config.RuleActionChallengeConfig{
			DifficultyBits: 30,
			WorkUnits:      64,
		},
	}
	settings = manager.settings(action)
	if settings.WorkUnits != 64 {
		t.Fatalf("expected explicit calibrated work units to win, got %d", settings.WorkUnits)
	}

	provider.cfg.Challenges.PoW.WorkUnits = 128
	action.Challenge.WorkUnits = 0
	settings = manager.settings(action)
	if settings.WorkUnits != 100000 {
		t.Fatalf("expected action difficulty to derive action work units, got %d", settings.WorkUnits)
	}
}

func TestChallengeSettingsPreservesExplicitZeroValues(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	provider.cfg.Challenges.DefaultTTLSeconds = testIntPtr(0)
	provider.cfg.Challenges.MinPageTimeMs = testIntPtr(0)
	provider.cfg.Challenges.MaxAttemptsPerWindow = testIntPtr(0)

	manager := NewChallengeManager(provider)
	defer manager.Stop()

	settings := manager.settings(nil)
	if settings.ClearanceTTL != 0 {
		t.Fatalf("expected explicit zero clearance TTL, got %v", settings.ClearanceTTL)
	}
	if settings.MinPageTime != 0 {
		t.Fatalf("expected explicit zero minimum page time, got %v", settings.MinPageTime)
	}
	if settings.MaxAttemptsPerWindow != 0 {
		t.Fatalf("expected explicit zero attempt limit, got %d", settings.MaxAttemptsPerWindow)
	}

	req := httptest.NewRequest(http.MethodPost, "https://example.com/fg-cgi/challenge/verify", nil)
	req.Host = "example.com"
	for i := 0; i < defaultAttemptLimit+2; i++ {
		if !manager.allowAttempt(req, settings) {
			t.Fatal("expected explicit zero attempt limit to disable attempt limiting")
		}
	}
}

func TestChallengeVerifyRejectsBeforeMinimumPageTime(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	provider.cfg.Challenges.MinPageTimeMs = testIntPtr(1000)
	manager := NewChallengeManager(provider)
	defer manager.Stop()

	rule := &config.Rule{ID: "admin-rule"}
	action := &config.RuleAction{
		ID:     "pow-action",
		Action: "challenge",
		Challenge: &config.RuleActionChallengeConfig{
			DifficultyBits: 1,
		},
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "test-browser")
	settings := manager.settings(action)
	token, err := manager.newChallengeToken(req, rule, action, settings)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	nonce, proof := solveChallengeProof(t, token, settings)

	form := url.Values{}
	form.Set("token", token)
	form.Set("nonce", nonce)
	form.Set("proof", proof)
	verifyReq := httptest.NewRequest(http.MethodPost, "https://example.com/fg-cgi/challenge/verify", strings.NewReader(form.Encode()))
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.Header.Set("User-Agent", "test-browser")
	verifyResp := httptest.NewRecorder()

	manager.handleChallengeVerify(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusTooEarly {
		t.Fatalf("expected early verify to be rejected, got %d body %q", verifyResp.Code, verifyResp.Body.String())
	}
	assertChallengeInfo(t, verifyReq, "verify_failed", "too_early", "admin-rule", "pow-action")
}

func TestChallengeVerifyFailureTelemetry(t *testing.T) {
	provider := newChallengeProvider(nil, nil)
	manager := NewChallengeManager(provider)
	defer manager.Stop()

	rule := &config.Rule{ID: "admin-rule"}
	action := &config.RuleAction{
		ID:     "pow-action",
		Action: "challenge",
		Challenge: &config.RuleActionChallengeConfig{
			DifficultyBits: 1,
		},
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "test-browser")
	settings := manager.settings(action)
	token, err := manager.newChallengeToken(req, rule, action, settings)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	missingReq := httptest.NewRequest(http.MethodPost, "https://example.com/fg-cgi/challenge/verify", nil)
	missingReq.Host = "example.com"
	missingResp := httptest.NewRecorder()
	manager.handleChallengeVerify(missingResp, missingReq)
	if missingResp.Code != http.StatusBadRequest {
		t.Fatalf("expected missing proof to be bad request, got %d", missingResp.Code)
	}
	assertChallengeInfo(t, missingReq, "verify_failed", "missing_proof", "", "")

	form := url.Values{}
	form.Set("token", token)
	form.Set("nonce", "bad")
	form.Set("proof", "bad")
	invalidReq := httptest.NewRequest(http.MethodPost, "https://example.com/fg-cgi/challenge/verify", strings.NewReader(form.Encode()))
	invalidReq.Host = "example.com"
	invalidReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	invalidReq.Header.Set("User-Agent", "test-browser")
	invalidResp := httptest.NewRecorder()
	manager.handleChallengeVerify(invalidResp, invalidReq)
	if invalidResp.Code != http.StatusForbidden {
		t.Fatalf("expected invalid proof to be forbidden, got %d", invalidResp.Code)
	}
	assertChallengeInfo(t, invalidReq, "verify_failed", "invalid_proof", "admin-rule", "pow-action")
}

func TestVerifyPoWSupportsCalibratedPBKDF2AndSHA256(t *testing.T) {
	token := "test-token"

	pbkdf2Settings := challengeSettings{
		EffortMode:       config.PoWEffortModeCalibrated,
		Algorithm:        config.PoWAlgorithmPBKDF2SHA256,
		PBKDF2Iterations: 1,
		WorkUnits:        2,
	}
	pbkdf2Nonce, pbkdf2Proof := solveChallengeProof(t, token, pbkdf2Settings)
	if !verifyPoW(token, pbkdf2Nonce, pbkdf2Proof, pbkdf2Settings.EffortMode, pbkdf2Settings.Algorithm, pbkdf2Settings.PBKDF2Iterations, pbkdf2Settings.DifficultyBits, pbkdf2Settings.WorkUnits) {
		t.Fatal("expected calibrated PBKDF2 proof to verify")
	}

	shaSettings := challengeSettings{
		EffortMode: config.PoWEffortModeCalibrated,
		Algorithm:  config.PoWAlgorithmSHA256,
		WorkUnits:  2,
	}
	shaNonce, shaProof := solveChallengeProof(t, token, shaSettings)
	if !verifyPoW(token, shaNonce, shaProof, shaSettings.EffortMode, shaSettings.Algorithm, shaSettings.PBKDF2Iterations, shaSettings.DifficultyBits, shaSettings.WorkUnits) {
		t.Fatal("expected calibrated SHA-256 proof to verify")
	}
}

func TestVerifyPoWSupportsProbabilisticMode(t *testing.T) {
	token := "test-token"
	settings := challengeSettings{
		EffortMode:       config.PoWEffortModeProbabilistic,
		Algorithm:        config.PoWAlgorithmPBKDF2SHA256,
		PBKDF2Iterations: 1,
		DifficultyBits:   1,
		WorkUnits:        1,
	}
	nonce, proof := solveChallengeProof(t, token, settings)
	if proof != "" {
		t.Fatalf("expected probabilistic mode to omit proof, got %q", proof)
	}
	if !verifyPoW(token, nonce, proof, settings.EffortMode, settings.Algorithm, settings.PBKDF2Iterations, settings.DifficultyBits, settings.WorkUnits) {
		t.Fatal("expected probabilistic proof to verify")
	}
}

func TestChallengePassedCanStillBeBlockedByLaterRule(t *testing.T) {
	rules := map[string]*config.Rule{
		"challenge-admin": {
			ID:        "challenge-admin",
			Action:    "challenge-action",
			SortOrder: 1,
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
		"block-admin": {
			ID:        "block-admin",
			Action:    "block-action",
			SortOrder: 2,
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
	}
	actions := map[string]*config.RuleAction{
		"challenge-action": {
			ID:     "challenge-action",
			Action: "challenge",
			Challenge: &config.RuleActionChallengeConfig{
				DifficultyBits: 1,
			},
		},
		"block-action": {
			ID:      "block-action",
			Action:  "block",
			Status:  http.StatusUnavailableForLegalReasons,
			Message: "Blocked after challenge",
		},
	}
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	cookie := issueChallengeCookie(t, rm.challenges, rules["challenge-admin"], actions["challenge-action"])
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "test-browser")
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()

	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("expected later block rule to stop proxy handler")
	}))

	if resp.Code != http.StatusUnavailableForLegalReasons {
		t.Fatalf("expected later block status, got %d", resp.Code)
	}
	if got := GetRuleMatched(req); got == nil || got.ID != "block-admin" {
		t.Fatalf("expected block rule context, got %#v", got)
	}
	if got := GetRuleResult(req); got != "block" {
		t.Fatalf("expected final rule result block, got %q", got)
	}
	assertChallengeInfo(t, req, "passed", "", "challenge-admin", "challenge-action")
}

func TestChallengePassedCanStillBeRateLimitedByLaterRule(t *testing.T) {
	rules := map[string]*config.Rule{
		"challenge-admin": {
			ID:        "challenge-admin",
			Action:    "challenge-action",
			SortOrder: 1,
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
		"rate-limit-admin": {
			ID:        "rate-limit-admin",
			Action:    "rate-limit-action",
			SortOrder: 2,
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
	}
	actions := map[string]*config.RuleAction{
		"challenge-action": {
			ID:     "challenge-action",
			Action: "challenge",
			Challenge: &config.RuleActionChallengeConfig{
				DifficultyBits: 1,
			},
		},
		"rate-limit-action": {
			ID:                "rate-limit-action",
			Action:            "rate_limit",
			Status:            http.StatusTooManyRequests,
			Message:           "Rate limited after challenge",
			RequestsPerWindow: 1,
			WindowSeconds:     60,
		},
	}
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	cookie := issueChallengeCookie(t, rm.challenges, rules["challenge-admin"], actions["challenge-action"])
	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "test-browser")
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()
	rm.Handle(resp, req, nextHandler)
	if resp.Code != http.StatusOK {
		t.Fatalf("expected first cleared request through rate limit, got %d", resp.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "test-browser")
	req.AddCookie(cookie)
	resp = httptest.NewRecorder()
	rm.Handle(resp, req, nextHandler)
	if resp.Code != http.StatusTooManyRequests {
		t.Fatalf("expected second cleared request to hit rate limit, got %d", resp.Code)
	}
	if got := GetRuleResult(req); got != "rate_limit" {
		t.Fatalf("expected final rule result rate_limit, got %q", got)
	}
	assertChallengeInfo(t, req, "passed", "", "challenge-admin", "challenge-action")
}

func TestFirstMatchingChallengeRuleWins(t *testing.T) {
	rules := map[string]*config.Rule{
		"challenge-first": {
			ID:        "challenge-first",
			Action:    "challenge-first-action",
			SortOrder: 1,
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
		"challenge-second": {
			ID:        "challenge-second",
			Action:    "challenge-second-action",
			SortOrder: 2,
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
	}
	actions := map[string]*config.RuleAction{
		"challenge-first-action": {
			ID:     "challenge-first-action",
			Action: "challenge",
			Challenge: &config.RuleActionChallengeConfig{
				DifficultyBits: 1,
			},
		},
		"challenge-second-action": {
			ID:     "challenge-second-action",
			Action: "challenge",
			Challenge: &config.RuleActionChallengeConfig{
				DifficultyBits: 1,
			},
		},
	}
	provider := newChallengeProvider(rules, actions)
	rm := NewRulesMiddleware(provider)
	defer rm.Stop()

	cookie := issueChallengeCookie(t, rm.challenges, rules["challenge-first"], actions["challenge-first-action"])
	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("Accept", "text/html")
	req.Header.Set("User-Agent", "test-browser")
	req.AddCookie(cookie)
	resp := httptest.NewRecorder()

	handlerCalled := false
	rm.Handle(resp, req, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	if !handlerCalled {
		t.Fatal("expected first challenge clearance to allow proxy handler")
	}
	if resp.Code != http.StatusOK {
		t.Fatalf("expected cleared request to proxy, got %d", resp.Code)
	}
	if got := resp.Header().Get("X-FlowGuard-Action"); got != "" {
		t.Fatalf("expected later challenge rule to be skipped, got challenge header %q", got)
	}
	assertChallengeInfo(t, req, "passed", "", "challenge-first", "challenge-first-action")
}

func newChallengeProvider(rules map[string]*config.Rule, actions map[string]*config.RuleAction) *challengeMockConfigProvider {
	disabled := false
	return &challengeMockConfigProvider{
		cfg: &config.Config{
			Host: &config.HostConfig{Key: "test-secret"},
			Challenges: &config.ChallengesConfig{
				BindIP:               &disabled,
				BindUserAgent:        &disabled,
				MinPageTimeMs:        testIntPtr(0),
				MaxAttemptsPerWindow: testIntPtr(20),
				AttemptWindowSeconds: testIntPtr(60),
				PoW: &config.PoWChallengeConfig{
					DifficultyBits:   1,
					PBKDF2Iterations: 1,
					WorkUnits:        1,
				},
			},
		},
		rules:   rules,
		actions: actions,
	}
}

func challengeRulesAndActions() (map[string]*config.Rule, map[string]*config.RuleAction) {
	rules := map[string]*config.Rule{
		"challenge-admin": {
			ID:     "challenge-admin",
			Name:   "Challenge admin",
			Action: "challenge-action",
			Conditions: &config.RuleConditions{
				Matches: []config.MatchCondition{{Type: "path", Match: "starts-with", Value: "/admin"}},
			},
		},
	}
	actions := map[string]*config.RuleAction{
		"challenge-action": {
			ID:     "challenge-action",
			Name:   "Challenge action",
			Action: "challenge",
			Challenge: &config.RuleActionChallengeConfig{
				DifficultyBits: 1,
			},
		},
	}
	return rules, actions
}

func issueChallengeCookie(t *testing.T, manager *ChallengeManager, rule *config.Rule, action *config.RuleAction) *http.Cookie {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "https://example.com/admin", nil)
	req.Host = "example.com"
	req.Header.Set("User-Agent", "test-browser")
	settings := manager.settings(action)
	token, err := manager.newChallengeToken(req, rule, action, settings)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	nonce, proof := solveChallengeProof(t, token, settings)

	form := url.Values{}
	form.Set("token", token)
	form.Set("nonce", nonce)
	form.Set("proof", proof)
	verifyReq := httptest.NewRequest(http.MethodPost, "https://example.com/fg-cgi/challenge/verify", strings.NewReader(form.Encode()))
	verifyReq.Host = "example.com"
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.Header.Set("User-Agent", "test-browser")
	verifyResp := httptest.NewRecorder()
	manager.handleChallengeVerify(verifyResp, verifyReq)
	if verifyResp.Code != http.StatusSeeOther {
		t.Fatalf("expected verify redirect, got %d body %q", verifyResp.Code, verifyResp.Body.String())
	}

	cookies := verifyResp.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one clearance cookie, got %d", len(cookies))
	}
	return cookies[0]
}

func solveChallengeProof(t *testing.T, token string, settings challengeSettings) (string, string) {
	t.Helper()

	if settings.EffortMode == config.PoWEffortModeCalibrated {
		proof, ok := computeCalibratedProof(token, settings.Algorithm, settings.PBKDF2Iterations, settings.WorkUnits)
		if !ok {
			t.Fatalf("failed to solve calibrated %s challenge", settings.Algorithm)
		}
		return strconv.Itoa(settings.WorkUnits), proof
	}

	for nonce := 0; nonce < 1_000_000; nonce++ {
		candidate := strconv.Itoa(nonce)
		if verifyPoW(token, candidate, "", settings.EffortMode, settings.Algorithm, settings.PBKDF2Iterations, settings.DifficultyBits, settings.WorkUnits) {
			return candidate, ""
		}
	}
	t.Fatalf("failed to solve %s challenge at difficulty %d", settings.Algorithm, settings.DifficultyBits)
	return "", ""
}

func assertChallengeInfo(t *testing.T, r *http.Request, outcome string, reason string, ruleID string, actionID string) {
	t.Helper()

	info := GetChallengeInfo(r)
	if info == nil {
		t.Fatal("expected challenge telemetry")
	}
	if !info.Present {
		t.Fatal("expected challenge telemetry to be marked present")
	}
	if info.Outcome != outcome {
		t.Fatalf("expected challenge outcome %q, got %q", outcome, info.Outcome)
	}
	if info.Reason != reason {
		t.Fatalf("expected challenge reason %q, got %q", reason, info.Reason)
	}
	if ruleID == "" {
		if info.Rule != nil {
			t.Fatalf("expected no challenge rule reference, got %#v", info.Rule)
		}
	} else if info.Rule == nil || info.Rule.ID != ruleID {
		t.Fatalf("expected challenge rule ID %q, got %#v", ruleID, info.Rule)
	}
	if actionID == "" {
		if info.Action != nil {
			t.Fatalf("expected no challenge action reference, got %#v", info.Action)
		}
	} else if info.Action == nil || info.Action.ID != actionID {
		t.Fatalf("expected challenge action ID %q, got %#v", actionID, info.Action)
	}
}

func assertChallengeInfoNames(t *testing.T, r *http.Request, ruleName string, actionName string) {
	t.Helper()

	info := GetChallengeInfo(r)
	if info == nil {
		t.Fatal("expected challenge telemetry")
	}
	if info.Rule == nil || info.Rule.Name != ruleName {
		t.Fatalf("expected challenge rule name %q, got %#v", ruleName, info.Rule)
	}
	if info.Action == nil || info.Action.Name != actionName {
		t.Fatalf("expected challenge action name %q, got %#v", actionName, info.Action)
	}
}

func testIntPtr(v int) *int {
	return &v
}
