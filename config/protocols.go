package config

// DefaultProtocolSettings returns the protocol set used when config does not
// explicitly disable a protocol.
func DefaultProtocolSettings() ProtocolSettings {
	return ProtocolSettings{
		HTTP1: true,
		HTTP2: true,
		HTTP3: true,
	}
}

func (s ProtocolSettings) AnyEnabled() bool {
	return s.HTTP1 || s.HTTP2 || s.HTTP3
}

func (c *Config) ProtocolSettings() ProtocolSettings {
	if c == nil || c.Server == nil {
		return DefaultProtocolSettings()
	}

	return c.Server.ProtocolSettings()
}

func (s *ServerConfig) ProtocolSettings() ProtocolSettings {
	settings := DefaultProtocolSettings()
	if s == nil || s.Protocols == nil {
		return settings
	}

	if s.Protocols.HTTP1 != nil {
		settings.HTTP1 = *s.Protocols.HTTP1
	}
	if s.Protocols.HTTP2 != nil {
		settings.HTTP2 = *s.Protocols.HTTP2
	}
	if s.Protocols.HTTP3 != nil {
		settings.HTTP3 = *s.Protocols.HTTP3
	}

	return settings
}
