package middleware

import "net/http"

type Fail2BanMatcher interface {
	MatchingJails(ip string) []string
}

type Fail2BanMiddleware struct {
	matcher Fail2BanMatcher
}

func NewFail2BanMiddleware(matcher Fail2BanMatcher) *Fail2BanMiddleware {
	return &Fail2BanMiddleware{matcher: matcher}
}

func (m *Fail2BanMiddleware) Handle(w http.ResponseWriter, r *http.Request, next http.Handler) {
	if m.matcher == nil {
		next.ServeHTTP(w, r)
		return
	}
	jails := m.matcher.MatchingJails(GetClientIP(r))
	if len(jails) == 0 {
		next.ServeHTTP(w, r)
		return
	}

	SetRuleResult(r, "block")
	SetFail2BanInfo(r, RequestLogEntryFail2BanInfo{Jails: jails})
	writeBlockedResponse(w, r, http.StatusForbidden, "Forbidden")
}

func (m *Fail2BanMiddleware) Stop() {}
