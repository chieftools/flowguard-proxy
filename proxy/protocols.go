package proxy

import (
	"net/http"

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
