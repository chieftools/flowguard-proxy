package config

import "testing"

func TestFail2BanEnabled(t *testing.T) {
	var nilConfig *Config
	if nilConfig.Fail2BanEnabled() || (&Config{}).Fail2BanEnabled() {
		t.Fatal("missing Fail2Ban configuration must be disabled")
	}
	if !(&Config{Fail2Ban: &Fail2BanConfig{Enabled: true}}).Fail2BanEnabled() {
		t.Fatal("explicit Fail2Ban configuration was not enabled")
	}
}
