package fail2ban

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type runnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func (f runnerFunc) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return f(ctx, name, args...)
}

func TestParseJailList(t *testing.T) {
	jails, err := parseJailList("Status\n|- Number of jail:\t3\n`- Jail list:\tweb-scan, ssh-test, web-scan")
	if err != nil {
		t.Fatalf("parseJailList: %v", err)
	}
	want := []string{"ssh-test", "web-scan"}
	if !reflect.DeepEqual(jails, want) {
		t.Fatalf("jails = %#v, want %#v", jails, want)
	}
}

func TestBannedPrefixesQueriesCompleteJailListWithoutFilter(t *testing.T) {
	var commandArgs []string
	controller := &controller{
		clientPath:     "fail2ban-client",
		commandTimeout: time.Second,
		runner: runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			commandArgs = append([]string(nil), args...)
			return []byte("198.51.100.17 203.0.113.0/28"), nil
		}),
	}

	prefixes, err := controller.bannedPrefixes(context.Background(), "request-limit")
	if err != nil {
		t.Fatalf("bannedPrefixes: %v", err)
	}
	if want := []string{"get", "request-limit", "banip"}; !reflect.DeepEqual(commandArgs, want) {
		t.Fatalf("command arguments = %#v, want %#v", commandArgs, want)
	}
	if want := []string{"198.51.100.17/32", "203.0.113.0/28"}; !reflect.DeepEqual(prefixes, want) {
		t.Fatalf("prefixes = %#v, want %#v", prefixes, want)
	}
}

func TestManagerTracksOverlappingJailsAndCIDRs(t *testing.T) {
	manager := NewManager(Options{})
	manager.SetEnabled(true)
	manager.applyEvent(Event{Operation: "ban", Jail: "web-scan", Address: "198.51.100.44"})
	manager.applyEvent(Event{Operation: "ban", Jail: "repeat-offender", Address: "198.51.100.0/24"})

	if got := manager.MatchingJails("198.51.100.44"); !reflect.DeepEqual(got, []string{"repeat-offender", "web-scan"}) {
		t.Fatalf("matching jails = %#v", got)
	}
	manager.applyEvent(Event{Operation: "unban", Jail: "web-scan", Address: "198.51.100.44"})
	if got := manager.MatchingJails("198.51.100.44"); !reflect.DeepEqual(got, []string{"repeat-offender"}) {
		t.Fatalf("matching jails after one unban = %#v", got)
	}
	manager.applyEvent(Event{Operation: "unban", Jail: "repeat-offender", Address: "198.51.100.0/24"})
	if got := manager.MatchingJails("198.51.100.44"); len(got) != 0 {
		t.Fatalf("matching jails after final unban = %#v", got)
	}
}

func TestManagerStopsMatchingImmediatelyWhenDisabled(t *testing.T) {
	manager := NewManager(Options{})
	manager.SetEnabled(true)
	manager.replaceJail("request-limit", []string{"192.0.2.117"})
	if got := manager.MatchingJails("192.0.2.117"); !reflect.DeepEqual(got, []string{"request-limit"}) {
		t.Fatalf("enabled matches = %#v", got)
	}

	manager.SetEnabled(false)
	if got := manager.MatchingJails("192.0.2.117"); len(got) != 0 {
		t.Fatalf("disabled matches = %#v", got)
	}
}

func TestReconcileRetainsFailedJailAndRemovesVanishedJail(t *testing.T) {
	manager := NewManager(Options{})
	manager.SetEnabled(true)
	manager.replaceJail("web-scan", []string{"192.0.2.31"})
	manager.replaceJail("retired-jail", []string{"192.0.2.32"})

	runner := runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "status":
			return []byte("Status\n`- Jail list: web-scan, api-abuse"), nil
		case "get web-scan banip":
			return nil, errors.New("temporary query failure")
		case "get api-abuse banip":
			return []byte("203.0.113.64\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	})
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", runner: runner, commandTimeout: time.Second}
	snapshotted := map[string]struct{}{"web-scan": {}, "retired-jail": {}}
	if _, err := manager.reconcile(context.Background(), controller, false, true, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, snapshotted); err == nil {
		t.Fatal("reconcile succeeded despite a failed jail snapshot")
	}
	if got := manager.MatchingJails("192.0.2.31"); !reflect.DeepEqual(got, []string{"web-scan"}) {
		t.Fatalf("last-known jail was not retained: %#v", got)
	}
	if got := manager.MatchingJails("192.0.2.32"); len(got) != 0 {
		t.Fatalf("vanished jail was retained: %#v", got)
	}
	if got := manager.MatchingJails("203.0.113.64"); !reflect.DeepEqual(got, []string{"api-abuse"}) {
		t.Fatalf("new jail was not loaded: %#v", got)
	}
	if _, ok := snapshotted["web-scan"]; ok {
		t.Fatal("failed jail remained marked as snapshotted")
	}
	if _, ok := snapshotted["api-abuse"]; !ok {
		t.Fatal("successfully queried jail was not marked as snapshotted")
	}
	if _, ok := snapshotted["retired-jail"]; ok {
		t.Fatal("vanished jail remained marked as snapshotted")
	}
}

func TestReconcileRetriesOnlyJailsMissingSnapshotsDuringActionAudit(t *testing.T) {
	manager := NewManager(Options{})
	manager.SetEnabled(true)
	manager.replaceJail("web-scan", []string{"192.0.2.31"})
	banListQueries := make(map[string]int)
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second}
	controller.runner = runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "status":
			return []byte("Status\n`- Jail list: web-scan, api-abuse"), nil
		case "get web-scan banip":
			banListQueries["web-scan"]++
			return []byte("198.51.100.73"), nil
		case "get api-abuse banip":
			banListQueries["api-abuse"]++
			return []byte("203.0.113.79"), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	snapshotted := map[string]struct{}{"api-abuse": {}}

	if _, err := manager.reconcile(context.Background(), controller, false, false, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, snapshotted); err != nil {
		t.Fatalf("retry reconciliation: %v", err)
	}
	if banListQueries["web-scan"] != 1 {
		t.Fatalf("failed jail query count = %d, want 1", banListQueries["web-scan"])
	}
	if banListQueries["api-abuse"] != 0 {
		t.Fatalf("healthy jail query count = %d, want 0", banListQueries["api-abuse"])
	}
	if got := manager.MatchingJails("198.51.100.73"); !reflect.DeepEqual(got, []string{"web-scan"}) {
		t.Fatalf("retried jail was not refreshed: %#v", got)
	}
}

func TestActionAuditDoesNotReloadExistingBanLists(t *testing.T) {
	manager := NewManager(Options{})
	manager.replaceJail("web-scan", []string{"192.0.2.31"})
	banListQueries := 0
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second}
	controller.runner = runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "status":
			return []byte("Status\n`- Jail list: web-scan"), nil
		case "get web-scan actions":
			return []byte("flowguard-runtime"), nil
		case "get web-scan action flowguard-runtime actionban":
			return []byte(controller.actionCommand("ban", "web-scan")), nil
		case "get web-scan action flowguard-runtime actionunban":
			return []byte(controller.actionCommand("unban", "web-scan")), nil
		case "get web-scan banip":
			banListQueries++
			return []byte("192.0.2.31"), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	owned := map[string]struct{}{"web-scan": {}}
	collisions := map[string]struct{}{}
	snapshotted := map[string]struct{}{"web-scan": {}}

	if _, err := manager.reconcile(context.Background(), controller, true, false, owned, map[string]struct{}{}, collisions, snapshotted); err != nil {
		t.Fatalf("action audit: %v", err)
	}
	if banListQueries != 0 {
		t.Fatalf("action audit made %d ban-list queries", banListQueries)
	}
	if _, err := manager.reconcile(context.Background(), controller, true, true, owned, map[string]struct{}{}, collisions, snapshotted); err != nil {
		t.Fatalf("full snapshot: %v", err)
	}
	if banListQueries != 1 {
		t.Fatalf("full snapshot made %d ban-list queries, want 1", banListQueries)
	}
}

func TestActionAuditSnapshotsReattachedJailImmediately(t *testing.T) {
	manager := NewManager(Options{})
	manager.SetEnabled(true)
	manager.replaceJail("web-scan", []string{"192.0.2.41"})
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second}
	controller.runner = runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "status":
			return []byte("Status\n`- Jail list: web-scan"), nil
		case "get web-scan actions":
			return []byte("standard-firewall"), nil
		case "get web-scan action flowguard-runtime actionban":
			return nil, errors.New("action not found")
		case "set web-scan addaction flowguard-runtime",
			"set web-scan action flowguard-runtime actionban '/usr/bin/flowguard' fail2ban-event 'ban' 'web-scan' '<ip>'",
			"set web-scan action flowguard-runtime actionunban '/usr/bin/flowguard' fail2ban-event 'unban' 'web-scan' '<ip>'",
			"set web-scan action flowguard-runtime timeout 1":
			return nil, nil
		case "get web-scan banip":
			return []byte("198.51.100.42"), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	owned := map[string]struct{}{"web-scan": {}}
	snapshotted := map[string]struct{}{"web-scan": {}}
	if _, err := manager.reconcile(context.Background(), controller, true, false, owned, map[string]struct{}{}, map[string]struct{}{}, snapshotted); err != nil {
		t.Fatalf("action audit: %v", err)
	}
	if got := manager.MatchingJails("192.0.2.41"); len(got) != 0 {
		t.Fatalf("stale snapshot remained after reattach: %#v", got)
	}
	if got := manager.MatchingJails("198.51.100.42"); !reflect.DeepEqual(got, []string{"web-scan"}) {
		t.Fatalf("reattached jail was not snapshotted: %#v", got)
	}
}

func TestEnsureActionPreservesCollision(t *testing.T) {
	setCalled := false
	runner := runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "set" {
			setCalled = true
		}
		if args[len(args)-1] == "actionban" {
			return []byte("/usr/local/bin/unrelated ban"), nil
		}
		return []byte("/usr/local/bin/unrelated unban"), nil
	})
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", runner: runner, commandTimeout: time.Second}
	status, err := controller.ensureAction(context.Background(), "web-scan")
	if err != nil {
		t.Fatalf("ensureAction: %v", err)
	}
	if status != actionCollision || setCalled {
		t.Fatalf("status = %v, setCalled = %t", status, setCalled)
	}
}

func TestEnsureActionConfiguresRuntimeHook(t *testing.T) {
	var calls []string
	runner := runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		calls = append(calls, joined)
		if joined == "get web-scan action flowguard-runtime actionban" {
			return nil, errors.New("action not found")
		}
		return nil, nil
	})
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/opt/flow guard/bin/flowguard", runner: runner, commandTimeout: time.Second}
	status, err := controller.ensureAction(context.Background(), "web-scan")
	if err != nil {
		t.Fatalf("ensureAction: %v", err)
	}
	if status != actionAttached {
		t.Fatalf("status = %v", status)
	}
	want := []string{
		"get web-scan action flowguard-runtime actionban",
		"set web-scan addaction flowguard-runtime",
		"set web-scan action flowguard-runtime actionban '/opt/flow guard/bin/flowguard' fail2ban-event 'ban' 'web-scan' '<ip>'",
		"set web-scan action flowguard-runtime actionunban '/opt/flow guard/bin/flowguard' fail2ban-event 'unban' 'web-scan' '<ip>'",
		"set web-scan action flowguard-runtime timeout 1",
	}
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("commands = %#v, want %#v", calls, want)
	}
}

func TestReconcileRetriesCleanupAfterPartialActionConfiguration(t *testing.T) {
	manager := NewManager(Options{})
	present := false
	failConfiguration := true
	failCleanup := true
	deleteCalls := 0
	controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second}
	controller.runner = runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "status":
			return []byte("Status\n`- Jail list: request-limit"), nil
		case "get request-limit action flowguard-runtime actionban":
			if !present {
				return nil, errors.New("action not found")
			}
			return []byte(controller.actionCommand("ban", "request-limit")), nil
		case "set request-limit addaction flowguard-runtime":
			present = true
			return nil, nil
		case "set request-limit action flowguard-runtime actionban '/usr/bin/flowguard' fail2ban-event 'ban' 'request-limit' '<ip>'":
			return nil, nil
		case "set request-limit action flowguard-runtime actionunban '/usr/bin/flowguard' fail2ban-event 'unban' 'request-limit' '<ip>'":
			if failConfiguration {
				failConfiguration = false
				return nil, errors.New("temporary property update failure")
			}
			return nil, nil
		case "set request-limit action flowguard-runtime timeout 1":
			return nil, nil
		case "set request-limit delaction flowguard-runtime":
			deleteCalls++
			if failCleanup {
				failCleanup = false
				return nil, errors.New("temporary action removal failure")
			}
			present = false
			return nil, nil
		case "get request-limit actions":
			if present {
				return []byte("flowguard-runtime"), nil
			}
			return []byte("standard-firewall"), nil
		case "get request-limit banip":
			return []byte("198.51.100.143"), nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	owned := map[string]struct{}{}
	cleanupPending := map[string]struct{}{}
	collisions := map[string]struct{}{}
	snapshotted := map[string]struct{}{}

	_, err := manager.reconcile(context.Background(), controller, true, true, owned, cleanupPending, collisions, snapshotted)
	if err == nil || !strings.Contains(err.Error(), "temporary property update failure") || !strings.Contains(err.Error(), "temporary action removal failure") {
		t.Fatalf("initial reconciliation error = %v", err)
	}
	if _, ok := owned["request-limit"]; !ok {
		t.Fatal("partially configured action was not retained as owned")
	}
	if _, ok := cleanupPending["request-limit"]; !ok {
		t.Fatal("partially configured action was not scheduled for cleanup")
	}
	if _, ok := collisions["request-limit"]; ok {
		t.Fatal("partially configured action was classified as a collision")
	}

	if _, err := manager.reconcile(context.Background(), controller, true, true, owned, cleanupPending, collisions, snapshotted); err != nil {
		t.Fatalf("retry reconciliation: %v", err)
	}
	if deleteCalls != 2 {
		t.Fatalf("runtime action delete attempts = %d, want 2", deleteCalls)
	}
	if _, ok := cleanupPending["request-limit"]; ok {
		t.Fatal("successful cleanup remained pending")
	}
	if _, ok := owned["request-limit"]; !ok {
		t.Fatal("reconfigured runtime action was not recorded as owned")
	}
}

func TestRemoveOwnedActionPropagatesActionQueryFailures(t *testing.T) {
	for _, failedProperty := range []string{"actionban", "actionunban"} {
		t.Run(failedProperty, func(t *testing.T) {
			controller := &controller{clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second}
			controller.runner = runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch joined {
				case "get web-scan actions":
					return []byte("The jail web-scan has the following actions:\nflowguard-runtime"), nil
				case "get web-scan action flowguard-runtime actionban":
					if failedProperty == "actionban" {
						return nil, errors.New("temporary action query failure")
					}
					return []byte(controller.actionCommand("ban", "web-scan")), nil
				case "get web-scan action flowguard-runtime actionunban":
					return nil, errors.New("temporary action query failure")
				default:
					return nil, errors.New("unexpected command: " + joined)
				}
			})

			if err := controller.removeOwnedAction(context.Background(), "web-scan"); err == nil || !strings.Contains(err.Error(), "temporary action query failure") {
				t.Fatalf("cleanup error = %v", err)
			}
		})
	}
}

func TestRemoveOwnedActionTreatsConfirmedMissingActionAsNoOp(t *testing.T) {
	propertyQueried := false
	controller := &controller{
		clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second,
		runner: runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if strings.Join(args, " ") == "get web-scan actions" {
				return []byte("The jail web-scan has the following actions:\nstandard-firewall"), nil
			}
			propertyQueried = true
			return nil, errors.New("unexpected property query")
		}),
	}
	if err := controller.removeOwnedAction(context.Background(), "web-scan"); err != nil {
		t.Fatalf("remove missing action: %v", err)
	}
	if propertyQueried {
		t.Fatal("queried properties for a confirmed missing action")
	}
}

func TestRemoveOwnedActionHandlesActionDisappearingDuringCleanup(t *testing.T) {
	actionsQueries := 0
	controller := &controller{
		clientPath: "fail2ban-client", flowguardPath: "/usr/bin/flowguard", commandTimeout: time.Second,
		runner: runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if joined == "get web-scan actions" {
				actionsQueries++
				if actionsQueries == 1 {
					return []byte("flowguard-runtime"), nil
				}
				return []byte("standard-firewall"), nil
			}
			if joined == "get web-scan action flowguard-runtime actionban" {
				return nil, errors.New("action disappeared")
			}
			return nil, errors.New("unexpected command: " + joined)
		}),
	}
	if err := controller.removeOwnedAction(context.Background(), "web-scan"); err != nil {
		t.Fatalf("remove disappearing action: %v", err)
	}
}

func TestRuntimeActionCleanupUsesFreshTimeoutPerJail(t *testing.T) {
	secondJailQueried := false
	manager := NewManager(Options{
		ClientPath:     "fail2ban-client",
		FlowGuardPath:  "/usr/bin/flowguard",
		CommandTimeout: 20 * time.Millisecond,
		Runner: runnerFunc(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch joined {
			case "get a-slow-jail actions":
				<-ctx.Done()
				return nil, ctx.Err()
			case "get b-later-jail actions":
				secondJailQueried = true
				return []byte("standard-firewall"), nil
			default:
				return nil, errors.New("unexpected command: " + joined)
			}
		}),
	})

	manager.cleanupOwnedActions(map[string]struct{}{
		"a-slow-jail":  {},
		"b-later-jail": {},
	}, map[string]struct{}{})
	if !secondJailQueried {
		t.Fatal("later jail did not receive a cleanup attempt after the first timeout")
	}
}

func TestRuntimeActionCleanupHonorsOverallTimeout(t *testing.T) {
	var queried []string
	manager := NewManager(Options{
		ClientPath:     "fail2ban-client",
		FlowGuardPath:  "/usr/bin/flowguard",
		CommandTimeout: 50 * time.Millisecond,
		CleanupTimeout: 20 * time.Millisecond,
		Runner: runnerFunc(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			queried = append(queried, args[1])
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	})

	started := time.Now()
	manager.cleanupOwnedActions(map[string]struct{}{
		"first-jail":  {},
		"second-jail": {},
		"third-jail":  {},
	}, map[string]struct{}{})
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("cleanup took %s, want at most 100ms", elapsed)
	}
	if !reflect.DeepEqual(queried, []string{"first-jail"}) {
		t.Fatalf("queried jails = %#v, want only the first jail", queried)
	}
}

type lifecycleRunner struct {
	mu       sync.RWMutex
	statusOK bool
	pingOK   bool
}

func (r *lifecycleRunner) setHealth(statusOK, pingOK bool) {
	r.mu.Lock()
	r.statusOK = statusOK
	r.pingOK = pingOK
	r.mu.Unlock()
}

func (r *lifecycleRunner) CombinedOutput(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.mu.RLock()
	statusOK, pingOK := r.statusOK, r.pingOK
	r.mu.RUnlock()
	joined := strings.Join(args, " ")
	switch {
	case joined == "status":
		if !statusOK {
			return nil, errors.New("daemon query failed")
		}
		return []byte("Status\n`- Jail list: web-scan"), nil
	case joined == "ping":
		if !pingOK {
			return nil, errors.New("daemon is unavailable")
		}
		return []byte("Server replied: pong"), nil
	case joined == "get web-scan banip":
		return []byte("198.51.100.71"), nil
	case joined == "get web-scan actions":
		return []byte("The jail web-scan has the following actions:\nflowguard-runtime"), nil
	case joined == "get web-scan action flowguard-runtime actionban":
		return []byte("'/usr/bin/flowguard' fail2ban-event 'ban' 'web-scan' '<ip>'"), nil
	case joined == "get web-scan action flowguard-runtime actionunban":
		return []byte("'/usr/bin/flowguard' fail2ban-event 'unban' 'web-scan' '<ip>'"), nil
	case joined == "set web-scan delaction flowguard-runtime":
		return nil, nil
	default:
		return nil, errors.New("unexpected command: " + joined)
	}
}

func TestManagerRetainsInconclusiveStateAndClearsOnDaemonLoss(t *testing.T) {
	runner := &lifecycleRunner{}
	runner.setHealth(true, true)
	temporary, err := os.CreateTemp("", "flowguard-fail2ban-")
	if err != nil {
		t.Fatalf("create temporary socket path: %v", err)
	}
	socketPath := temporary.Name() + ".sock"
	temporary.Close()
	os.Remove(temporary.Name())
	t.Cleanup(func() { _ = os.Remove(socketPath) })
	manager := NewManager(Options{
		ClientPath:          "fail2ban-client",
		FlowGuardPath:       "/usr/bin/flowguard",
		EventSocketPath:     socketPath,
		GOOS:                "linux",
		ActionCheckInterval: 20 * time.Millisecond,
		SnapshotInterval:    20 * time.Millisecond,
		RetryInterval:       10 * time.Millisecond,
		CommandTimeout:      100 * time.Millisecond,
		Runner:              runner,
	})
	manager.SetEnabled(true)
	manager.Start()
	t.Cleanup(manager.Stop)
	waitFor(t, func() bool { return len(manager.MatchingJails("198.51.100.71")) == 1 })

	if err := SendEvent(manager.options.EventSocketPath, Event{Operation: "ban", Jail: "web-scan", Address: "203.0.113.88"}); err != nil {
		t.Fatalf("SendEvent: %v", err)
	}
	waitFor(t, func() bool { return len(manager.MatchingJails("203.0.113.88")) == 1 })

	runner.setHealth(false, true)
	time.Sleep(60 * time.Millisecond)
	if got := manager.MatchingJails("198.51.100.71"); len(got) != 1 {
		t.Fatalf("transient failure cleared state: %#v", got)
	}

	runner.setHealth(false, false)
	waitFor(t, func() bool { return len(manager.MatchingJails("198.51.100.71")) == 0 })
}

func TestManagerClearsBansBeforeRuntimeActionCleanupCompletes(t *testing.T) {
	temporary, err := os.CreateTemp("", "flowguard-disable-")
	if err != nil {
		t.Fatalf("create temporary socket path: %v", err)
	}
	socketPath := temporary.Name() + ".sock"
	temporary.Close()
	os.Remove(temporary.Name())
	t.Cleanup(func() { _ = os.Remove(socketPath) })

	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var signalCleanup sync.Once
	runner := runnerFunc(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "status":
			return []byte("Status\n`- Jail list: request-limit"), nil
		case "get request-limit banip":
			return []byte("198.51.100.117"), nil
		case "get request-limit action flowguard-runtime actionban":
			return []byte("'/usr/bin/flowguard' fail2ban-event 'ban' 'request-limit' '<ip>'"), nil
		case "get request-limit action flowguard-runtime actionunban":
			return []byte("'/usr/bin/flowguard' fail2ban-event 'unban' 'request-limit' '<ip>'"), nil
		case "get request-limit actions":
			signalCleanup.Do(func() { close(cleanupStarted) })
			select {
			case <-releaseCleanup:
				return []byte("flowguard-runtime"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		case "set request-limit delaction flowguard-runtime":
			return nil, nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	manager := NewManager(Options{
		ClientPath:          "fail2ban-client",
		FlowGuardPath:       "/usr/bin/flowguard",
		EventSocketPath:     socketPath,
		GOOS:                "linux",
		ActionCheckInterval: time.Hour,
		SnapshotInterval:    time.Hour,
		CommandTimeout:      time.Second,
		CleanupTimeout:      time.Second,
		Runner:              runner,
	})
	manager.SetEnabled(true)
	manager.Start()
	t.Cleanup(manager.Stop)
	waitFor(t, func() bool { return len(manager.MatchingJails("198.51.100.117")) == 1 })

	manager.SetEnabled(false)
	select {
	case <-cleanupStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime-action cleanup did not start")
	}
	if got := manager.MatchingJails("198.51.100.117"); len(got) != 0 {
		t.Fatalf("disabled integration retained bans during cleanup: %#v", got)
	}
	close(releaseCleanup)
}

func TestManagerInitialAttemptWaitsForBanSnapshot(t *testing.T) {
	eventPath := filepath.Join(t.TempDir(), "occupied-event-path")
	if err := os.WriteFile(eventPath, []byte("reserved"), 0o600); err != nil {
		t.Fatalf("create occupied event path: %v", err)
	}
	statusStarted := make(chan struct{})
	releaseStatus := make(chan struct{})
	var signalStatus sync.Once
	manager := NewManager(Options{
		ClientPath:      "fail2ban-client",
		FlowGuardPath:   "/usr/bin/flowguard",
		EventSocketPath: eventPath,
		GOOS:            "linux",
		CommandTimeout:  time.Second,
		Runner: runnerFunc(func(ctx context.Context, _ string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch joined {
			case "status":
				signalStatus.Do(func() { close(statusStarted) })
				select {
				case <-releaseStatus:
					return []byte("Status\n`- Jail list: request-limit"), nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			case "get request-limit banip":
				return []byte("203.0.113.149"), nil
			default:
				return nil, errors.New("unexpected command: " + joined)
			}
		}),
	})
	manager.SetEnabled(true)
	initialAttempt := manager.Start()
	t.Cleanup(manager.Stop)

	select {
	case <-statusStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("initial jail query did not start")
	}
	select {
	case <-initialAttempt:
		t.Fatal("initial attempt completed before the jail query")
	default:
	}
	close(releaseStatus)
	select {
	case <-initialAttempt:
	case <-time.After(2 * time.Second):
		t.Fatal("initial attempt did not complete after the snapshot")
	}
	if got := manager.MatchingJails("203.0.113.149"); !reflect.DeepEqual(got, []string{"request-limit"}) {
		t.Fatalf("initial ban snapshot was not available: %#v", got)
	}
}

func TestManagerRetriesRuntimeEventServerCreation(t *testing.T) {
	temporary, err := os.CreateTemp("", "flowguard-event-retry-")
	if err != nil {
		t.Fatalf("create occupied event path: %v", err)
	}
	eventPath := temporary.Name()
	if err := temporary.Close(); err != nil {
		t.Fatalf("close occupied event path: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(eventPath) })
	actionAttached := make(chan struct{})
	statusQueries := make(chan struct{}, 8)
	var signalAttached sync.Once
	actionConfigured := false
	controller := &controller{flowguardPath: "/usr/bin/flowguard"}
	runner := runnerFunc(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch joined {
		case "status":
			select {
			case statusQueries <- struct{}{}:
			default:
			}
			return []byte("Status\n`- Jail list: request-limit"), nil
		case "get request-limit banip":
			return []byte("198.51.100.163"), nil
		case "get request-limit action flowguard-runtime actionban":
			if !actionConfigured {
				return nil, errors.New("action not found")
			}
			return []byte(controller.actionCommand("ban", "request-limit")), nil
		case "get request-limit action flowguard-runtime actionunban":
			return []byte(controller.actionCommand("unban", "request-limit")), nil
		case "get request-limit actions":
			if actionConfigured {
				return []byte("flowguard-runtime"), nil
			}
			return []byte("standard-firewall"), nil
		case "set request-limit addaction flowguard-runtime",
			"set request-limit action flowguard-runtime actionban '/usr/bin/flowguard' fail2ban-event 'ban' 'request-limit' '<ip>'",
			"set request-limit action flowguard-runtime actionunban '/usr/bin/flowguard' fail2ban-event 'unban' 'request-limit' '<ip>'":
			return nil, nil
		case "set request-limit action flowguard-runtime timeout 1":
			actionConfigured = true
			signalAttached.Do(func() { close(actionAttached) })
			return nil, nil
		case "set request-limit delaction flowguard-runtime":
			actionConfigured = false
			return nil, nil
		default:
			return nil, errors.New("unexpected command: " + joined)
		}
	})
	manager := NewManager(Options{
		ClientPath:          "fail2ban-client",
		FlowGuardPath:       controller.flowguardPath,
		EventSocketPath:     eventPath,
		GOOS:                "linux",
		ActionCheckInterval: time.Hour,
		SnapshotInterval:    time.Hour,
		RetryInterval:       20 * time.Millisecond,
		CommandTimeout:      200 * time.Millisecond,
		Runner:              runner,
	})
	manager.SetEnabled(true)
	initialAttempt := manager.Start()
	t.Cleanup(manager.Stop)
	select {
	case <-initialAttempt:
	case <-time.After(2 * time.Second):
		t.Fatal("initial reconciliation did not finish")
	}
	select {
	case <-statusQueries:
	default:
		t.Fatal("initial reconciliation did not query active jails")
	}
	select {
	case <-actionAttached:
		t.Fatal("runtime action attached while the event path was unavailable")
	default:
	}
	if err := os.Remove(eventPath); err != nil {
		t.Fatalf("release event path: %v", err)
	}
	select {
	case <-statusQueries:
	case <-time.After(2 * time.Second):
		t.Fatal("event-server retry did not trigger reconciliation")
	}
	select {
	case <-actionAttached:
	case <-time.After(2 * time.Second):
		t.Fatal("runtime event server and action were not restored")
	}

	if err := SendEvent(eventPath, Event{Operation: "ban", Jail: "request-limit", Address: "203.0.113.167"}); err != nil {
		t.Fatalf("send restored runtime event: %v", err)
	}
	waitFor(t, func() bool { return len(manager.MatchingJails("203.0.113.167")) == 1 })

	if err := os.Remove(eventPath); err != nil {
		t.Fatalf("remove runtime event socket path: %v", err)
	}
	sendEventEventually(t, eventPath, Event{Operation: "ban", Jail: "request-limit", Address: "192.0.2.173"})
	waitFor(t, func() bool { return len(manager.MatchingJails("192.0.2.173")) == 1 })
}

func sendEventEventually(t *testing.T, socketPath string, event Event) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = SendEvent(socketPath, event); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("event was not accepted before timeout: %v", err)
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
