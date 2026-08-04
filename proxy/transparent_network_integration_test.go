//go:build linux

package proxy

import (
	"os"
	"testing"

	"flowguard/config"
)

func TestTransparentNetworkSourceRoundTripIntegration(t *testing.T) {
	if os.Getenv("FLOWGUARD_TRANSPARENT_INTEGRATION") != "1" {
		t.Skip("set FLOWGUARD_TRANSPARENT_INTEGRATION=1 inside an isolated network namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("transparent network integration test requires root in the network namespace")
	}

	settings := config.TransparentUpstreamSettings{
		FWMark:          27991,
		RouteTable:      27991,
		RulePriority:    27991,
		MaxClientPools:  8,
		PoolIdleSeconds: 5,
	}
	manager := newTransparentNetworkManager(settings, []string{"192.0.2.10"})
	if err := manager.Setup(); err != nil {
		t.Fatalf("setup transparent networking and prove source round trip: %v", err)
	}
	t.Cleanup(manager.Cleanup)

	missing, err := manager.Check()
	if err != nil {
		t.Fatalf("check transparent networking: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("transparent networking is incomplete after setup: %v", missing)
	}
}
