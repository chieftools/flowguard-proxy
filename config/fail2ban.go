package config

// Fail2BanEnabled reports whether the optional Fail2Ban synchronization is enabled.
func (c *Config) Fail2BanEnabled() bool {
	return c != nil && c.Fail2Ban != nil && c.Fail2Ban.Enabled
}
