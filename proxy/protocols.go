package proxy

import (
	"net/http"
	"strings"

	"flowguard/config"
)

func tlsNextProtos(settings config.ProtocolSettings) []string {
	protos := make([]string, 0, 2)

	if settings.HTTP2 {
		protos = append(protos, "h2")
	}

	if settings.HTTP1 {
		protos = append(protos, "http/1.1")
	}

	return protos
}

func httpServerProtocols(settings config.ProtocolSettings, tlsEnabled bool) *http.Protocols {
	protos := &http.Protocols{}

	protos.SetHTTP1(settings.HTTP1)

	if tlsEnabled {
		protos.SetHTTP2(settings.HTTP2)
	}

	return protos
}

func addAltSvcValue(header http.Header, value string) {
	for _, existing := range header.Values("Alt-Svc") {
		if altSvcContainsHTTP3(existing) {
			return
		}
	}

	header.Add("Alt-Svc", value)
}

func altSvcContainsHTTP3(value string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(part)), "h3=") {
			return true
		}
	}

	return false
}
