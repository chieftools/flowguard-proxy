package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"flowguard/config"

	"golang.org/x/crypto/pbkdf2"
)

const (
	FlowGuardCGIPrefix          = "/fg-cgi/"
	challengePath               = "/fg-cgi/challenge"
	challengeVerifyPath         = "/fg-cgi/challenge/verify"
	defaultChallengeCookieName  = "fg_clearance"
	defaultClearanceTTLSeconds  = 1800
	defaultChallengeTTLSeconds  = 120
	defaultMinPageTimeMs        = 1500
	defaultChallengeDifficulty  = 18
	defaultPoWAlgorithm         = config.PoWAlgorithmPBKDF2SHA256
	defaultPBKDF2Iterations     = 100
	defaultPoWEffortMode        = config.PoWEffortModeCalibrated
	defaultPoWWorkUnits         = 128
	defaultNonHTMLStatus        = http.StatusAccepted
	defaultAttemptLimit         = 20
	defaultAttemptWindowSeconds = 60
	challengeTokenVersion       = "fgv1"
)

type challengeConfigProvider interface {
	GetConfig() *config.Config
}

type ChallengeManager struct {
	configProvider ConfigProvider
	attemptLimiter *RateLimiter

	mu                  sync.Mutex
	processSecret       []byte
	consumedChallenges  map[string]time.Time
	warnedProcessSecret bool
}

type challengeSettings struct {
	CookieName           string
	ClearanceTTL         time.Duration
	ChallengeTTL         time.Duration
	MinPageTime          time.Duration
	DifficultyBits       int
	Algorithm            string
	PBKDF2Iterations     int
	EffortMode           string
	WorkUnits            int
	BindIP               bool
	BindUserAgent        bool
	NonHTMLStatus        int
	MaxAttemptsPerWindow int
	AttemptWindow        time.Duration
	Secret               []byte
}

type challengeTokenPayload struct {
	Type                string `json:"typ"`
	ID                  string `json:"id,omitempty"`
	Host                string `json:"host,omitempty"`
	RuleID              string `json:"rule,omitempty"`
	RuleName            string `json:"rule_name,omitempty"`
	ActionID            string `json:"action,omitempty"`
	ActionName          string `json:"action_name,omitempty"`
	Scope               string `json:"scope,omitempty"`
	DifficultyBits      int    `json:"difficulty,omitempty"`
	Algorithm           string `json:"algorithm,omitempty"`
	PBKDF2Iterations    int    `json:"pbkdf2_iterations,omitempty"`
	EffortMode          string `json:"effort_mode,omitempty"`
	WorkUnits           int    `json:"work_units,omitempty"`
	MinPageTimeMs       int    `json:"min_page_time_ms,omitempty"`
	ClearanceTTLSeconds int    `json:"clearance_ttl,omitempty"`
	ReturnTo            string `json:"return_to,omitempty"`
	IPHash              string `json:"iph,omitempty"`
	UAHash              string `json:"uah,omitempty"`
	IssuedAt            int64  `json:"iat"`
	IssuedAtMs          int64  `json:"iat_ms,omitempty"`
	ExpiresAt           int64  `json:"exp"`
}

type challengePageData struct {
	Message          string
	StreamID         string
	Token            string
	DifficultyBits   int
	Algorithm        string
	PBKDF2Iterations int
	EffortMode       string
	WorkUnits        int
	MinPageTimeMs    int
	VerifyPath       string
}

var challengePageTemplate = template.Must(template.New("challenge").Parse(challengeHTML))

func NewChallengeManager(configProvider ConfigProvider) *ChallengeManager {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		secret = sum[:]
	}

	return &ChallengeManager{
		configProvider:     configProvider,
		processSecret:      secret,
		attemptLimiter:     NewRateLimiter(time.Minute * 10),
		consumedChallenges: make(map[string]time.Time),
	}
}

func (cm *ChallengeManager) Stop() {
	if cm != nil && cm.attemptLimiter != nil {
		cm.attemptLimiter.Stop()
	}
}

func (cm *ChallengeManager) HandleInternal(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case challengePath:
		cm.handleChallengePage(w, r)
	case challengeVerifyPath:
		cm.handleChallengeVerify(w, r)
	default:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "FlowGuard endpoint not found\n")
	}
}

func (cm *ChallengeManager) HasValidClearance(r *http.Request, rule *config.Rule, action *config.RuleAction) bool {
	valid, _, _ := cm.ClearanceStatus(r, rule, action)
	return valid
}

func (cm *ChallengeManager) ClearanceStatus(r *http.Request, rule *config.Rule, action *config.RuleAction) (bool, string, challengeTokenPayload) {
	var payload challengeTokenPayload
	if cm == nil || r == nil || rule == nil || action == nil {
		return false, "unavailable", payload
	}

	settings := cm.settings(action)
	cookie, err := r.Cookie(settings.CookieName)
	if err != nil || cookie.Value == "" {
		return false, "missing_proof", payload
	}

	if err := cm.verifySignedToken(cookie.Value, settings.Secret, &payload); err != nil {
		return false, "invalid_token", payload
	}

	now := time.Now().Unix()
	if payload.Type != "clearance" {
		return false, "invalid_token", payload
	}
	if payload.ExpiresAt != 0 && payload.ExpiresAt <= now {
		return false, "expired", payload
	}

	scope := effectiveClearanceScope(action)
	host := normalizedHost(r.Host)
	if payload.Scope != scope {
		return false, "invalid_token", payload
	}
	if payload.Host != host {
		return false, "host_mismatch", payload
	}

	switch scope {
	case config.ChallengeScopeRule:
		if payload.RuleID != rule.ID || payload.ActionID != action.ID {
			return false, "invalid_token", payload
		}
	case config.ChallengeScopeHost:
		// Host-scoped clearances can satisfy multiple challenge rules on this host.
	default:
		return false, "invalid_token", payload
	}

	if settings.BindIP && payload.IPHash != cm.bindingHash(settings.Secret, "ip", requestClientIP(r)) {
		return false, "ip_mismatch", payload
	}
	if settings.BindUserAgent && payload.UAHash != cm.bindingHash(settings.Secret, "ua", r.Header.Get("User-Agent")) {
		return false, "user_agent_mismatch", payload
	}

	return true, "", payload
}

func (cm *ChallengeManager) ChallengeRequest(w http.ResponseWriter, r *http.Request, rule *config.Rule, action *config.RuleAction) {
	settings := cm.settings(action)
	token, err := cm.newChallengeToken(r, rule, action, settings)
	if err != nil {
		log.Printf("[middleware:challenge] Failed to create challenge token: %v", err)
		if info := GetChallengeInfo(r); info != nil {
			info.Reason = "unavailable"
			SetChallengeInfo(r, *info)
		}
		http.Error(w, "Challenge unavailable", http.StatusServiceUnavailable)
		return
	}

	challengeURL := challengePath + "?token=" + url.QueryEscape(token)
	w.Header().Set("X-FlowGuard-Action", "challenge")
	w.Header().Set("X-FlowGuard-Challenge-URL", challengeURL)
	w.Header().Add("Via", fmt.Sprintf("%d.%d flowguard", r.ProtoMajor, r.ProtoMinor))
	w.Header().Add("FG-Stream", GetStreamID(r))

	if isInteractiveChallengeRequest(r) {
		status := action.Status
		if status == 0 {
			status = http.StatusForbidden
		}
		cm.renderChallengePage(w, r, status, action.Message, token, settings)
		return
	}

	cm.writeNonHTMLChallenge(w, r, settings.NonHTMLStatus, challengeURL)
}

func (cm *ChallengeManager) handleChallengePage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "Missing challenge token", http.StatusBadRequest)
		return
	}

	payload, settings, err := cm.verifyChallengeTokenForRequest(r, token)
	if err != nil {
		http.Error(w, "Invalid or expired challenge", http.StatusForbidden)
		return
	}

	settings.DifficultyBits = payload.DifficultyBits
	settings.Algorithm = payload.Algorithm
	settings.PBKDF2Iterations = payload.PBKDF2Iterations
	settings.EffortMode = payload.EffortMode
	settings.WorkUnits = payload.WorkUnits
	settings.MinPageTime = time.Duration(payload.MinPageTimeMs) * time.Millisecond
	cm.renderChallengePage(w, r, http.StatusForbidden, "", token, settings)
}

func (cm *ChallengeManager) handleChallengeVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	token := r.FormValue("token")
	nonce := r.FormValue("nonce")
	proof := r.FormValue("proof")
	if token == "" || nonce == "" {
		setChallengeVerifyInfo(r, "verify_failed", "missing_proof", challengeTokenPayload{})
		http.Error(w, "Missing challenge proof", http.StatusBadRequest)
		return
	}

	payload, settings, err := cm.verifyChallengeTokenForRequest(r, token)
	if err != nil {
		setChallengeVerifyInfo(r, "verify_failed", challengeReasonFromError(err), payload)
		http.Error(w, "Invalid or expired challenge", http.StatusForbidden)
		return
	}

	if !cm.allowAttempt(r, settings) {
		setChallengeVerifyInfo(r, "verify_failed", "attempt_limited", payload)
		http.Error(w, "Too many challenge attempts", http.StatusTooManyRequests)
		return
	}

	minPageTime := time.Duration(payload.MinPageTimeMs) * time.Millisecond
	issuedAt := time.Unix(payload.IssuedAt, 0)
	if payload.IssuedAtMs > 0 {
		issuedAt = time.UnixMilli(payload.IssuedAtMs)
	}
	if minPageTime > 0 && time.Now().Before(issuedAt.Add(minPageTime)) {
		setChallengeVerifyInfo(r, "verify_failed", "too_early", payload)
		http.Error(w, "Challenge submitted too quickly", http.StatusTooEarly)
		return
	}

	if !verifyPoW(token, nonce, proof, payload.EffortMode, payload.Algorithm, payload.PBKDF2Iterations, payload.DifficultyBits, payload.WorkUnits) {
		setChallengeVerifyInfo(r, "verify_failed", "invalid_proof", payload)
		http.Error(w, "Invalid challenge proof", http.StatusForbidden)
		return
	}

	if !cm.consumeChallenge(payload.ID, time.Unix(payload.ExpiresAt, 0)) {
		setChallengeVerifyInfo(r, "verify_failed", "replayed", payload)
		http.Error(w, "Challenge already used", http.StatusForbidden)
		return
	}

	clearanceTTL := settings.ClearanceTTL
	if payload.ClearanceTTLSeconds >= 0 {
		clearanceTTL = time.Duration(payload.ClearanceTTLSeconds) * time.Second
	}

	clearance, err := cm.newClearanceToken(r, payload, settings)
	if err != nil {
		log.Printf("[middleware:challenge] Failed to create clearance token: %v", err)
		setChallengeVerifyInfo(r, "verify_failed", "unavailable", payload)
		http.Error(w, "Challenge unavailable", http.StatusServiceUnavailable)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     settings.CookieName,
		Value:    clearance,
		Path:     "/",
		MaxAge:   int(clearanceTTL.Seconds()),
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})

	setChallengeVerifyInfo(r, "verify_success", "", payload)
	http.Redirect(w, r, safeReturnTo(payload.ReturnTo), http.StatusSeeOther)
}

func challengeIssuedOutcome(r *http.Request) string {
	if isInteractiveChallengeRequest(r) {
		return "issued_html"
	}
	return "issued_non_html"
}

func setChallengeVerifyInfo(r *http.Request, outcome string, reason string, payload challengeTokenPayload) {
	SetChallengeInfo(r, RequestLogEntryChallengeInfo{
		Outcome: outcome,
		Reason:  reason,
		Rule:    challengeRuleRefFromPayload(payload),
		Action:  challengeActionRefFromPayload(payload),
		Scope:   payload.Scope,
	})
}

func challengeRuleRef(rule *config.Rule) *RequestLogEntryChallengeRefInfo {
	if rule == nil || rule.ID == "" {
		return nil
	}
	return &RequestLogEntryChallengeRefInfo{
		ID:   rule.ID,
		Name: rule.Name,
	}
}

func challengeActionRef(action *config.RuleAction) *RequestLogEntryChallengeRefInfo {
	if action == nil || action.ID == "" {
		return nil
	}
	return &RequestLogEntryChallengeRefInfo{
		ID:   action.ID,
		Name: action.Name,
	}
}

func challengeRuleRefFromPayload(payload challengeTokenPayload) *RequestLogEntryChallengeRefInfo {
	if payload.RuleID == "" {
		return nil
	}
	return &RequestLogEntryChallengeRefInfo{
		ID:   payload.RuleID,
		Name: payload.RuleName,
	}
}

func challengeActionRefFromPayload(payload challengeTokenPayload) *RequestLogEntryChallengeRefInfo {
	if payload.ActionID == "" {
		return nil
	}
	return &RequestLogEntryChallengeRefInfo{
		ID:   payload.ActionID,
		Name: payload.ActionName,
	}
}

func challengeReasonFromError(err error) string {
	if err == nil {
		return ""
	}

	switch err.Error() {
	case "expired challenge":
		return "expired"
	case "host mismatch":
		return "host_mismatch"
	case "ip mismatch":
		return "ip_mismatch"
	case "user-agent mismatch":
		return "user_agent_mismatch"
	default:
		return "invalid_token"
	}
}

func (cm *ChallengeManager) newChallengeToken(r *http.Request, rule *config.Rule, action *config.RuleAction, settings challengeSettings) (string, error) {
	if settings.ChallengeTTL <= 0 {
		return "", errors.New("challenge ttl must be greater than zero")
	}

	now := time.Now()
	payload := challengeTokenPayload{
		Type:                "challenge",
		ID:                  randomTokenID(),
		Host:                normalizedHost(r.Host),
		RuleID:              rule.ID,
		RuleName:            rule.Name,
		ActionID:            action.ID,
		ActionName:          action.Name,
		Scope:               effectiveClearanceScope(action),
		DifficultyBits:      settings.DifficultyBits,
		Algorithm:           settings.Algorithm,
		PBKDF2Iterations:    settings.PBKDF2Iterations,
		EffortMode:          settings.EffortMode,
		WorkUnits:           settings.WorkUnits,
		MinPageTimeMs:       int(settings.MinPageTime / time.Millisecond),
		ClearanceTTLSeconds: int(settings.ClearanceTTL.Seconds()),
		ReturnTo:            safeReturnTo(r.URL.RequestURI()),
		IssuedAt:            now.Unix(),
		IssuedAtMs:          now.UnixMilli(),
		ExpiresAt:           now.Add(settings.ChallengeTTL).Unix(),
	}
	if settings.BindIP {
		payload.IPHash = cm.bindingHash(settings.Secret, "ip", requestClientIP(r))
	}
	if settings.BindUserAgent {
		payload.UAHash = cm.bindingHash(settings.Secret, "ua", r.Header.Get("User-Agent"))
	}
	return cm.signToken(payload, settings.Secret)
}

func (cm *ChallengeManager) newClearanceToken(r *http.Request, challenge challengeTokenPayload, settings challengeSettings) (string, error) {
	now := time.Now()
	if challenge.ClearanceTTLSeconds >= 0 {
		settings.ClearanceTTL = time.Duration(challenge.ClearanceTTLSeconds) * time.Second
	}
	payload := challengeTokenPayload{
		Type:       "clearance",
		Host:       challenge.Host,
		RuleID:     challenge.RuleID,
		RuleName:   challenge.RuleName,
		ActionID:   challenge.ActionID,
		ActionName: challenge.ActionName,
		Scope:      challenge.Scope,
		IPHash:     challenge.IPHash,
		UAHash:     challenge.UAHash,
		IssuedAt:   now.Unix(),
		ExpiresAt:  expiresAtUnix(now, settings.ClearanceTTL),
	}
	return cm.signToken(payload, settings.Secret)
}

func (cm *ChallengeManager) verifyChallengeTokenForRequest(r *http.Request, token string) (challengeTokenPayload, challengeSettings, error) {
	settings := cm.settings(nil)
	var payload challengeTokenPayload
	if err := cm.verifySignedToken(token, settings.Secret, &payload); err != nil {
		return payload, settings, err
	}

	if payload.Type != "challenge" {
		return payload, settings, errors.New("invalid token")
	}
	if payload.ExpiresAt <= time.Now().Unix() {
		return payload, settings, errors.New("expired challenge")
	}
	if payload.Host != normalizedHost(r.Host) {
		return payload, settings, errors.New("host mismatch")
	}
	if settings.BindIP && payload.IPHash != cm.bindingHash(settings.Secret, "ip", requestClientIP(r)) {
		return payload, settings, errors.New("ip mismatch")
	}
	if settings.BindUserAgent && payload.UAHash != cm.bindingHash(settings.Secret, "ua", r.Header.Get("User-Agent")) {
		return payload, settings, errors.New("user-agent mismatch")
	}
	if payload.DifficultyBits == 0 {
		payload.DifficultyBits = settings.DifficultyBits
	}
	if payload.Algorithm == "" {
		payload.Algorithm = settings.Algorithm
	}
	if payload.PBKDF2Iterations == 0 {
		payload.PBKDF2Iterations = settings.PBKDF2Iterations
	}
	if payload.EffortMode == "" {
		payload.EffortMode = settings.EffortMode
	}
	if payload.WorkUnits == 0 {
		payload.WorkUnits = settings.WorkUnits
	}
	if payload.MinPageTimeMs < 0 || payload.MinPageTimeMs > 60000 {
		return payload, settings, errors.New("invalid minimum page time")
	}
	if payload.DifficultyBits < 1 || payload.DifficultyBits > 30 {
		return payload, settings, errors.New("invalid difficulty")
	}
	if payload.Algorithm != config.PoWAlgorithmPBKDF2SHA256 && payload.Algorithm != config.PoWAlgorithmSHA256 {
		return payload, settings, errors.New("invalid algorithm")
	}
	if payload.PBKDF2Iterations < 1 || payload.PBKDF2Iterations > 100000 {
		return payload, settings, errors.New("invalid pbkdf2 iterations")
	}
	if payload.EffortMode != config.PoWEffortModeCalibrated && payload.EffortMode != config.PoWEffortModeProbabilistic {
		return payload, settings, errors.New("invalid effort mode")
	}
	if payload.WorkUnits < 1 || payload.WorkUnits > 100000 {
		return payload, settings, errors.New("invalid work units")
	}

	return payload, settings, nil
}

func (cm *ChallengeManager) signToken(payload challengeTokenPayload, secret []byte) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encoded := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(encoded))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return challengeTokenVersion + "." + encoded + "." + signature, nil
}

func (cm *ChallengeManager) verifySignedToken(token string, secret []byte, payload *challengeTokenPayload) error {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != challengeTokenVersion {
		return errors.New("invalid token")
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[1]))
	expected := mac.Sum(nil)

	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return err
	}
	if !hmac.Equal(got, expected) {
		return errors.New("invalid signature")
	}

	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return err
	}
	return json.Unmarshal(body, payload)
}

func (cm *ChallengeManager) bindingHash(secret []byte, kind string, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

func (cm *ChallengeManager) consumeChallenge(id string, expiresAt time.Time) bool {
	if id == "" {
		return false
	}

	now := time.Now()
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for challengeID, expires := range cm.consumedChallenges {
		if now.After(expires) {
			delete(cm.consumedChallenges, challengeID)
		}
	}

	if _, exists := cm.consumedChallenges[id]; exists {
		return false
	}
	cm.consumedChallenges[id] = expiresAt
	return true
}

func (cm *ChallengeManager) allowAttempt(r *http.Request, settings challengeSettings) bool {
	if settings.MaxAttemptsPerWindow == 0 || settings.AttemptWindow <= 0 {
		return true
	}

	key := "challenge:" + normalizedHost(r.Host) + ":" + requestClientIP(r)
	allowed, _, _ := cm.attemptLimiter.IsAllowed(key, settings.MaxAttemptsPerWindow, int(settings.AttemptWindow.Seconds()))
	return allowed
}

func (cm *ChallengeManager) settings(action *config.RuleAction) challengeSettings {
	workUnitsConfigured := false
	settings := challengeSettings{
		CookieName:           defaultChallengeCookieName,
		ClearanceTTL:         time.Duration(defaultClearanceTTLSeconds) * time.Second,
		ChallengeTTL:         time.Duration(defaultChallengeTTLSeconds) * time.Second,
		MinPageTime:          time.Duration(defaultMinPageTimeMs) * time.Millisecond,
		DifficultyBits:       defaultChallengeDifficulty,
		Algorithm:            defaultPoWAlgorithm,
		PBKDF2Iterations:     defaultPBKDF2Iterations,
		EffortMode:           defaultPoWEffortMode,
		BindIP:               true,
		BindUserAgent:        true,
		NonHTMLStatus:        defaultNonHTMLStatus,
		MaxAttemptsPerWindow: defaultAttemptLimit,
		AttemptWindow:        time.Duration(defaultAttemptWindowSeconds) * time.Second,
		Secret:               cm.processSecret,
	}

	if provider, ok := cm.configProvider.(challengeConfigProvider); ok {
		cfg := provider.GetConfig()
		if cfg != nil {
			if cfg.Host != nil && cfg.Host.Key != "" {
				settings.Secret = []byte(cfg.Host.Key)
			}
			if cfg.Challenges != nil {
				challenges := cfg.Challenges
				if challenges.Secret != "" {
					settings.Secret = []byte(challenges.Secret)
				}
				if challenges.CookieName != "" {
					settings.CookieName = challenges.CookieName
				}
				if challenges.DefaultTTLSeconds != nil {
					settings.ClearanceTTL = time.Duration(*challenges.DefaultTTLSeconds) * time.Second
				}
				if challenges.MinPageTimeMs != nil {
					settings.MinPageTime = time.Duration(*challenges.MinPageTimeMs) * time.Millisecond
				}
				if challenges.PoW != nil {
					if challenges.PoW.ChallengeTTLSeconds != nil {
						settings.ChallengeTTL = time.Duration(*challenges.PoW.ChallengeTTLSeconds) * time.Second
					}
					if challenges.PoW.DifficultyBits > 0 {
						settings.DifficultyBits = challenges.PoW.DifficultyBits
					}
					if challenges.PoW.Algorithm != "" {
						settings.Algorithm = challenges.PoW.Algorithm
					}
					if challenges.PoW.PBKDF2Iterations > 0 {
						settings.PBKDF2Iterations = challenges.PoW.PBKDF2Iterations
					}
					if challenges.PoW.EffortMode != "" {
						settings.EffortMode = challenges.PoW.EffortMode
					}
					if challenges.PoW.WorkUnits > 0 {
						settings.WorkUnits = challenges.PoW.WorkUnits
						workUnitsConfigured = true
					}
				}
				if challenges.BindIP != nil {
					settings.BindIP = *challenges.BindIP
				}
				if challenges.BindUserAgent != nil {
					settings.BindUserAgent = *challenges.BindUserAgent
				}
				if challenges.NonHTMLStatus > 0 {
					settings.NonHTMLStatus = challenges.NonHTMLStatus
				}
				if challenges.MaxAttemptsPerWindow != nil {
					settings.MaxAttemptsPerWindow = *challenges.MaxAttemptsPerWindow
				}
				if challenges.AttemptWindowSeconds != nil {
					settings.AttemptWindow = time.Duration(*challenges.AttemptWindowSeconds) * time.Second
				}
			}
		}
	}

	if action != nil && action.Challenge != nil {
		if action.Challenge.TTLSeconds != nil {
			settings.ClearanceTTL = time.Duration(*action.Challenge.TTLSeconds) * time.Second
		}
		if action.Challenge.MinPageTimeMs != nil {
			settings.MinPageTime = time.Duration(*action.Challenge.MinPageTimeMs) * time.Millisecond
		}
		if action.Challenge.DifficultyBits > 0 {
			settings.DifficultyBits = action.Challenge.DifficultyBits
			if action.Challenge.WorkUnits == 0 {
				workUnitsConfigured = false
			}
		}
		if action.Challenge.Algorithm != "" {
			settings.Algorithm = action.Challenge.Algorithm
		}
		if action.Challenge.PBKDF2Iterations > 0 {
			settings.PBKDF2Iterations = action.Challenge.PBKDF2Iterations
		}
		if action.Challenge.EffortMode != "" {
			settings.EffortMode = action.Challenge.EffortMode
		}
		if action.Challenge.WorkUnits > 0 {
			settings.WorkUnits = action.Challenge.WorkUnits
			workUnitsConfigured = true
		}
	}

	if !workUnitsConfigured {
		settings.WorkUnits = calibratedWorkUnitsForDifficulty(settings.DifficultyBits)
	}
	if settings.WorkUnits == 0 {
		settings.WorkUnits = defaultPoWWorkUnits
	}

	if string(settings.Secret) == string(cm.processSecret) {
		cm.warnProcessSecret()
	}

	return settings
}

func (cm *ChallengeManager) warnProcessSecret() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.warnedProcessSecret {
		return
	}
	cm.warnedProcessSecret = true
	log.Printf("[middleware:challenge] No challenges.secret or host.key configured; using process-local challenge secret, clearances will reset on restart")
}

func (cm *ChallengeManager) renderChallengePage(w http.ResponseWriter, r *http.Request, status int, message string, token string, settings challengeSettings) {
	if message == "" {
		message = "Security check required"
	}

	h := w.Header()
	h.Del("Content-Length")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	if r.Method == http.MethodHead {
		return
	}

	if err := challengePageTemplate.Execute(w, challengePageData{
		Message:          message,
		StreamID:         GetStreamID(r),
		Token:            token,
		DifficultyBits:   settings.DifficultyBits,
		Algorithm:        settings.Algorithm,
		PBKDF2Iterations: settings.PBKDF2Iterations,
		EffortMode:       settings.EffortMode,
		WorkUnits:        settings.WorkUnits,
		MinPageTimeMs:    int(settings.MinPageTime / time.Millisecond),
		VerifyPath:       challengeVerifyPath,
	}); err != nil {
		log.Printf("[middleware:challenge] Failed to render challenge page: %v", err)
	}
}

func (cm *ChallengeManager) writeNonHTMLChallenge(w http.ResponseWriter, r *http.Request, status int, challengeURL string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"type":          "https://flowguard.network/problems/challenge-required",
		"title":         "Challenge required",
		"status":        status,
		"challenge_url": challengeURL,
		"stream_id":     GetStreamID(r),
	})
}

func effectiveClearanceScope(action *config.RuleAction) string {
	if action != nil && action.Challenge != nil && action.Challenge.ClearanceScope != "" {
		return action.Challenge.ClearanceScope
	}
	return config.ChallengeScopeRule
}

func isInteractiveChallengeRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	return explicitlyAcceptsHTML(r)
}

func explicitlyAcceptsHTML(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(part, ";", 2)[0]))
		if mediaType == "text/html" || mediaType == "application/xhtml+xml" {
			return true
		}
	}
	return false
}

func requestClientIP(r *http.Request) string {
	clientIP := GetClientIP(r)
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(clientIP)
	if err == nil {
		return host
	}
	return clientIP
}

func normalizedHost(host string) string {
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		host = parsedHost
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func randomTokenID() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))
		return hex.EncodeToString(sum[:16])
	}
	return hex.EncodeToString(bytes)
}

func expiresAtUnix(now time.Time, ttl time.Duration) int64 {
	if ttl <= 0 {
		return 0
	}
	return now.Add(ttl).Unix()
}

func safeReturnTo(returnTo string) string {
	if returnTo == "" || !strings.HasPrefix(returnTo, "/") || strings.HasPrefix(returnTo, "//") {
		return "/"
	}
	if strings.HasPrefix(returnTo, FlowGuardCGIPrefix) {
		return "/"
	}
	return returnTo
}

func calibratedWorkUnitsForDifficulty(difficultyBits int) int {
	if difficultyBits < 1 {
		return defaultPoWWorkUnits
	}

	shift := difficultyBits - 5
	if shift < 0 {
		shift = 0
	}
	if shift >= 17 {
		return 100000
	}

	workUnits := 1 << shift
	if workUnits < 1 {
		return 1
	}
	if workUnits > 100000 {
		return 100000
	}
	return workUnits
}

func verifyPoW(token string, nonce string, proof string, effortMode string, algorithm string, pbkdf2Iterations int, difficultyBits int, workUnits int) bool {
	switch effortMode {
	case config.PoWEffortModeCalibrated:
		if nonce != fmt.Sprintf("%d", workUnits) {
			return false
		}
		expected, ok := computeCalibratedProof(token, algorithm, pbkdf2Iterations, workUnits)
		return ok && hmac.Equal([]byte(proof), []byte(expected))
	case config.PoWEffortModeProbabilistic:
		if difficultyBits < 1 || difficultyBits > 30 {
			return false
		}
		candidate, ok := computeProbabilisticProof(token, nonce, algorithm, pbkdf2Iterations)
		return ok && hasLeadingZeroBits(candidate, difficultyBits)
	default:
		return false
	}
}

func computeProbabilisticProof(token string, nonce string, algorithm string, pbkdf2Iterations int) ([]byte, bool) {
	switch algorithm {
	case config.PoWAlgorithmPBKDF2SHA256:
		if pbkdf2Iterations < 1 || pbkdf2Iterations > 100000 {
			return nil, false
		}
		return pbkdf2.Key([]byte(token), []byte("flowguard-pow-v1:"+nonce), pbkdf2Iterations, sha256.Size, sha256.New), true
	case config.PoWAlgorithmSHA256:
		sum := sha256.Sum256([]byte(token + ":" + nonce))
		return sum[:], true
	default:
		return nil, false
	}
}

func computeCalibratedProof(token string, algorithm string, pbkdf2Iterations int, workUnits int) (string, bool) {
	if workUnits < 1 || workUnits > 100000 {
		return "", false
	}

	state := []byte(token)
	for counter := 0; counter < workUnits; counter++ {
		switch algorithm {
		case config.PoWAlgorithmPBKDF2SHA256:
			if pbkdf2Iterations < 1 || pbkdf2Iterations > 100000 {
				return "", false
			}
			state = pbkdf2.Key(state, []byte(fmt.Sprintf("flowguard-pow-v1:%s:%d", token, counter)), pbkdf2Iterations, sha256.Size, sha256.New)
		case config.PoWAlgorithmSHA256:
			sum := sha256.Sum256(append(append([]byte(nil), state...), []byte(fmt.Sprintf(":%d", counter))...))
			state = sum[:]
		default:
			return "", false
		}
	}

	return hex.EncodeToString(state), true
}

func hasLeadingZeroBits(value []byte, bits int) bool {
	fullBytes := bits / 8
	for i := 0; i < fullBytes; i++ {
		if i >= len(value) || value[i] != 0 {
			return false
		}
	}

	remainingBits := bits % 8
	if remainingBits == 0 {
		return true
	}
	if fullBytes >= len(value) {
		return false
	}

	mask := byte(0xff << (8 - remainingBits))
	return value[fullBytes]&mask == 0
}

const challengeHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow">
  <title>Security Check | FlowGuard</title>
  <style>
    * { box-sizing: border-box; border: 0 solid; margin: 0; padding: 0; }
    html, body { height: 100%; margin: 0; padding: 0; }
    body {
      color: #111827;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }
    a { color: #16a085; text-decoration: none; }
    a:hover { text-decoration: underline; }
    #app { border-top: 4px solid #16a085; height: 100%; }
    .page { background: #fff; display: flex; flex-direction: column; min-height: 100%; padding-bottom: 3rem; padding-top: 4rem; }
    main { display: flex; flex-direction: column; flex-grow: 1; justify-content: center; margin: 0 auto; max-width: 80rem; padding-left: 1rem; padding-right: 1rem; width: 100%; }
    .panel { margin: 0 auto; max-width: 24rem; text-align: center; width: 100%; }
    .logo-wrap { color: #16a085; display: flex; justify-content: center; margin-bottom: 2rem; }
    .logo {
      animation: fg-pulse 1.6s ease-in-out infinite;
      fill: #16a085;
      height: 5rem;
      max-height: 5rem;
      max-width: 5rem;
      transform-origin: center;
      width: 5rem;
    }
    .logo-ring {
      animation: fg-ring 1.6s ease-in-out infinite;
      border: 2px solid rgba(22, 160, 133, .22);
      border-radius: 999px;
      height: 6rem;
      position: absolute;
      transform: translateY(-.5rem);
      width: 6rem;
    }
    .logo-stage { display: flex; justify-content: center; position: relative; }
    .message { color: #16a085; font-size: .875rem; font-weight: 600; letter-spacing: .025em; line-height: 1.25rem; text-transform: uppercase; }
    h1 { color: #111827; font-size: 1.5rem; font-weight: 800; line-height: 2rem; margin-top: .5rem; }
    p { color: #6b7280; font-size: .875rem; line-height: 1.25rem; margin-top: .5rem; }
    .status { color: #16a085; font-weight: 600; }
    footer { color: #9ca3af; flex-shrink: 0; font-size: .875rem; line-height: 1.25rem; margin: 0 auto; max-width: 80rem; padding-left: 1rem; padding-right: 1rem; text-align: center; width: 100%; }
    code { color: #9ca3af; cursor: pointer; font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Monaco, Consolas, monospace; user-select: all; }
    @keyframes fg-pulse {
      0%, 100% { opacity: .72; transform: scale(.96); }
      50% { opacity: 1; transform: scale(1.04); }
    }
    @keyframes fg-ring {
      0% { opacity: .65; transform: translateY(-.5rem) scale(.82); }
      70% { opacity: 0; transform: translateY(-.5rem) scale(1.22); }
      100% { opacity: 0; transform: translateY(-.5rem) scale(1.22); }
    }
    @media (min-width: 640px) {
      main, footer { padding-left: 1.5rem; padding-right: 1.5rem; }
    }
    @media (min-width: 1024px) {
      main, footer { padding-left: 2rem; padding-right: 2rem; }
    }
  </style>
</head>
<body class="h-full">
  <div id="app">
    <div class="page">
      <main>
        <div class="logo-stage" aria-hidden="true">
          <div class="logo-ring"></div>
          <div class="logo-wrap">
            <svg class="logo" viewBox="0 0 640 640" xmlns="http://www.w3.org/2000/svg"><path d="M64 391.3C64.1 393.5 64.4 395.7 65.1 397.9C69.1 410.5 82.6 417.6 95.2 413.6L100.1 412.1C150.1 396.3 184 350 184 297.6L184 296C184 212.1 252.1 144 336 144C362.1 144 386.6 150.6 408 162.1C344.3 173.4 296 229.1 296 296C296 344.6 335.4 384 384 384L387.1 384C398.7 384 410.2 381.8 421 377.5L431.2 373.4C441.3 369.4 448.2 368.5 453.1 369.7C460.6 371.6 468 375 474.6 380C495.3 395.6 520.6 410.7 548.8 414.5C561.9 416.3 574 407 575.8 393.9C575.9 392.9 576 392 576 391L576 518.4C575.9 506.7 567.1 496.5 555.2 494.9C539.3 492.8 522 483.6 503.5 469.7C465.1 440.7 413 440.7 374.5 469.7C350.5 487.8 333.8 496 320 496C306.2 496 289.5 487.8 265.5 469.7C227.1 440.7 175 440.7 136.5 469.7C118 483.6 100.7 492.8 84.8 494.9C72.9 496.5 64.2 506.6 64 518.2L64 391.3z" opacity=".4"></path><path d="M184 296C184 212.1 252.1 144 336 144C362.1 144 386.6 150.6 408 162.1C344.3 173.4 296 229.1 296 296C296 344.6 335.4 384 384 384L387.1 384C398.7 384 410.2 381.8 421 377.5L431.2 373.4C441.3 369.4 448.2 368.5 453.1 369.7C460.6 371.6 468 375 474.6 380C495.3 395.6 520.6 410.7 548.8 414.5C561.9 416.3 574 407 575.8 393.9C577.6 380.8 568.3 368.7 555.2 366.9C539.3 364.8 522 355.6 503.5 341.7C491.7 332.8 478.5 326.6 464.7 323.1C445.1 318.2 426.7 323.4 413.3 328.8L403.1 332.9C398 334.9 392.6 336 387.1 336L384 336C361.9 336 344 318.1 344 296C344 247.4 383.4 208 432 208C445.5 208 458.3 211 469.7 216.5C479.5 221.2 491.3 218.6 498.3 210.3C505.3 202 505.9 189.9 499.6 181C463.4 129.7 403.6 96 336 96C225.5 96 136 185.5 136 296L136 297.6C136 329 115.6 356.8 85.7 366.3L80.8 367.8C68.1 371.8 61.1 385.3 65.1 398C69.1 410.7 82.6 417.7 95.2 413.7L100.1 412.2C150.1 396.3 184 350 184 297.6L184 296zM403.4 508.1C424.7 492 453.3 492 474.6 508.1C495.3 523.7 520.6 538.8 548.8 542.6C561.9 544.4 574 535.1 575.8 522C577.6 508.9 568.3 496.8 555.2 495C539.3 492.9 522 483.7 503.5 469.8C465.1 440.8 413 440.8 374.5 469.8C350.5 487.9 333.8 496.1 320 496.1C306.2 496.1 289.5 487.9 265.5 469.8C227.1 440.8 175 440.8 136.5 469.8C118 483.7 100.7 492.9 84.8 495C71.7 496.8 62.4 508.8 64.2 522C66 535.2 78 544.4 91.2 542.6C119.4 538.8 144.8 523.7 165.4 508.1C186.7 492 215.3 492 236.6 508.1C260.8 526.4 288.9 544 320 544C351.1 544 379.1 526.3 403.4 508.1z"></path></svg>
          </div>
        </div>
        <section class="panel">
          <p class="message">{{.Message}}</p>
          <h1>Checking your browser before continuing</h1>
          <p>This process is automatic. FlowGuard is reviewing the request and will continue to the protected content shortly.</p>
          <p class="status" id="fg-status">Please wait while the check completes...</p>
          <noscript><p>JavaScript is required to complete this check and continue to the protected content.</p></noscript>
        </section>
      </main>
      <footer>Stream ID: <code>{{.StreamID}}</code> &middot; Powered by <a rel="noopener noreferrer" href="https://flowguard.network" target="_blank">FlowGuard</a></footer>
    </div>
  </div>
  <script>
  (function () {
    var token = {{.Token}};
    var difficulty = {{.DifficultyBits}};
    var algorithm = {{.Algorithm}};
    var pbkdf2Iterations = {{.PBKDF2Iterations}};
    var effortMode = {{.EffortMode}};
    var workUnits = {{.WorkUnits}};
    var minPageTimeMs = {{.MinPageTimeMs}};
    var verifyPath = {{.VerifyPath}};
    var status = document.getElementById("fg-status");
    var pageStartedAt = Date.now();

    function hex(bytes) {
      var out = "";
      for (var i = 0; i < bytes.length; i++) {
        out += bytes[i].toString(16).padStart(2, "0");
      }
      return out;
    }

    function concatBytes(a, b) {
      var out = new Uint8Array(a.length + b.length);
      out.set(a);
      out.set(b, a.length);
      return out;
    }

    function utf8Bytes(value) {
      if (window.TextEncoder) return new TextEncoder().encode(value);
      var encoded = unescape(encodeURIComponent(value));
      var out = new Uint8Array(encoded.length);
      for (var i = 0; i < encoded.length; i++) out[i] = encoded.charCodeAt(i);
      return out;
    }

    function rightRotate(value, amount) {
      return (value >>> amount) | (value << (32 - amount));
    }

    function sha256Fallback(bytes) {
      var k = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
      ];
      var h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
      var bitLength = bytes.length * 8;
      var paddedLength = (((bytes.length + 9 + 63) >> 6) << 6);
      var data = new Uint8Array(paddedLength);
      data.set(bytes);
      data[bytes.length] = 0x80;
      for (var i = 0; i < 8; i++) data[paddedLength - 1 - i] = (bitLength / Math.pow(256, i)) & 255;
      var w = new Array(64);
      for (var offset = 0; offset < data.length; offset += 64) {
        for (var j = 0; j < 16; j++) {
          var idx = offset + j * 4;
          w[j] = ((data[idx] << 24) | (data[idx + 1] << 16) | (data[idx + 2] << 8) | data[idx + 3]) >>> 0;
        }
        for (var j = 16; j < 64; j++) {
          var s0 = (rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3)) >>> 0;
          var s1 = (rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10)) >>> 0;
          w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
        }
        var a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (var j = 0; j < 64; j++) {
          var S1 = (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) >>> 0;
          var ch = ((e & f) ^ (~e & g)) >>> 0;
          var temp1 = (hh + S1 + ch + k[j] + w[j]) >>> 0;
          var S0 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) >>> 0;
          var maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
          var temp2 = (S0 + maj) >>> 0;
          hh = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
        }
        h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
        h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0; h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
      }
      var out = new Uint8Array(32);
      for (var i = 0; i < 8; i++) {
        out[i * 4] = (h[i] >>> 24) & 255;
        out[i * 4 + 1] = (h[i] >>> 16) & 255;
        out[i * 4 + 2] = (h[i] >>> 8) & 255;
        out[i * 4 + 3] = h[i] & 255;
      }
      return out;
    }

    function hmacSHA256Fallback(key, message) {
      if (key.length > 64) key = sha256Fallback(key);
      var ipad = new Uint8Array(64);
      var opad = new Uint8Array(64);
      for (var i = 0; i < 64; i++) {
        var v = i < key.length ? key[i] : 0;
        ipad[i] = v ^ 0x36;
        opad[i] = v ^ 0x5c;
      }
      return sha256Fallback(concatBytes(opad, sha256Fallback(concatBytes(ipad, message))));
    }

    function pbkdf2Fallback(password, salt, iterations) {
      var blockSalt = concatBytes(salt, new Uint8Array([0, 0, 0, 1]));
      var u = hmacSHA256Fallback(password, blockSalt);
      var out = new Uint8Array(u);
      for (var i = 1; i < iterations; i++) {
        u = hmacSHA256Fallback(password, u);
        for (var j = 0; j < out.length; j++) out[j] ^= u[j];
      }
      return out;
    }

    async function digestSHA256(bytes) {
      if (window.crypto && window.crypto.subtle) {
        return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
      }
      return sha256Fallback(bytes);
    }

    async function derivePBKDF2(password, salt, iterations) {
      if (window.crypto && window.crypto.subtle) {
        var key = await crypto.subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
        var bits = await crypto.subtle.deriveBits({
          name: "PBKDF2",
          salt: salt,
          iterations: iterations,
          hash: "SHA-256"
        }, key, 256);
        return new Uint8Array(bits);
      }
      return pbkdf2Fallback(password, salt, iterations);
    }

    function hasLeadingZeroBits(bytes, bits) {
      var fullBytes = Math.floor(bits / 8);
      for (var i = 0; i < fullBytes; i++) {
        if (bytes[i] !== 0) return false;
      }
      var remaining = bits % 8;
      if (remaining === 0) return true;
      var mask = 255 << (8 - remaining) & 255;
      return (bytes[fullBytes] & mask) === 0;
    }

    function submit(nonce, proof) {
      var form = document.createElement("form");
      form.method = "POST";
      form.action = verifyPath;
      var tokenInput = document.createElement("input");
      tokenInput.type = "hidden";
      tokenInput.name = "token";
      tokenInput.value = token;
      var nonceInput = document.createElement("input");
      nonceInput.type = "hidden";
      nonceInput.name = "nonce";
      nonceInput.value = String(nonce);
      var proofInput = document.createElement("input");
      proofInput.type = "hidden";
      proofInput.name = "proof";
      proofInput.value = proof || "";
      form.appendChild(tokenInput);
      form.appendChild(nonceInput);
      form.appendChild(proofInput);
      document.body.appendChild(form);
      form.submit();
    }

    async function waitForMinimumPageTime() {
      var remaining = minPageTimeMs - (Date.now() - pageStartedAt);
      if (remaining > 0) {
        await new Promise(function (resolve) { setTimeout(resolve, remaining); });
      }
    }

    async function solveSHA256() {
      for (var nonce = 0; nonce < 2147483647; nonce++) {
        var digest = await digestSHA256(utf8Bytes(token + ":" + nonce));
        if (hasLeadingZeroBits(digest, difficulty)) return nonce;
        if (nonce % 1000 === 0) await new Promise(function (resolve) { setTimeout(resolve, 0); });
      }
      return null;
    }

    async function solvePBKDF2() {
      var password = utf8Bytes(token);
      for (var nonce = 0; nonce < 2147483647; nonce++) {
        var bits = await derivePBKDF2(password, utf8Bytes("flowguard-pow-v1:" + nonce), pbkdf2Iterations);
        if (hasLeadingZeroBits(bits, difficulty)) return nonce;
        if (nonce % 100 === 0) await new Promise(function (resolve) { setTimeout(resolve, 0); });
      }
      return null;
    }

    async function calibratedStep(state, counter) {
      if (algorithm === "pbkdf2-sha256") {
        return await derivePBKDF2(state, utf8Bytes("flowguard-pow-v1:" + token + ":" + counter), pbkdf2Iterations);
      }
      if (algorithm === "sha256") {
        return await digestSHA256(concatBytes(state, utf8Bytes(":" + counter)));
      }
      return null;
    }

    async function solveCalibrated() {
      var state = utf8Bytes(token);
      for (var counter = 0; counter < workUnits; counter++) {
        state = await calibratedStep(state, counter);
        if (!state) return null;
        if (counter % 25 === 0) await new Promise(function (resolve) { setTimeout(resolve, 0); });
      }
      return { nonce: workUnits, proof: hex(state) };
    }

    async function solve() {
      if (!window.Uint8Array || !window.Promise) {
        status.textContent = "This browser cannot complete the automatic check.";
        return;
      }
      var result = null;
      if (effortMode === "calibrated") {
        result = await solveCalibrated();
      } else if (effortMode === "probabilistic" && algorithm === "pbkdf2-sha256") {
        var nonce = await solvePBKDF2();
        if (nonce !== null) result = { nonce: nonce, proof: "" };
      } else if (effortMode === "probabilistic" && algorithm === "sha256") {
        var nonce = await solveSHA256();
        if (nonce !== null) result = { nonce: nonce, proof: "" };
      } else {
        status.textContent = "This browser cannot complete the automatic check.";
        return;
      }
      if (result !== null) {
        status.textContent = "Check complete. Continuing shortly...";
        await waitForMinimumPageTime();
        submit(result.nonce, result.proof);
        return;
      }
      status.textContent = "The automatic check could not be completed.";
    }

    solve();
  })();
  </script>
</body>
</html>
`
