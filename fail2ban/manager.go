package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"flowguard/iplist"
)

type Options struct {
	ClientPath          string
	FlowGuardPath       string
	EventSocketPath     string
	GOOS                string
	ActionCheckInterval time.Duration
	SnapshotInterval    time.Duration
	RetryInterval       time.Duration
	CommandTimeout      time.Duration
	CleanupTimeout      time.Duration
	Runner              commandRunner
	Verbose             bool
}

type jailState struct {
	prefixes map[netip.Prefix]struct{}
	set      *iplist.Set
}

type Manager struct {
	options Options

	enabled  atomic.Bool
	started  atomic.Bool
	wake     chan struct{}
	events   chan Event
	cancel   context.CancelFunc
	done     chan struct{}
	initial  chan struct{}
	initOnce sync.Once

	stateMu sync.RWMutex
	jails   map[string]*jailState
}

func NewManager(options Options) *Manager {
	if options.EventSocketPath == "" {
		options.EventSocketPath = DefaultEventSocketPath
	}
	if options.GOOS == "" {
		options.GOOS = runtime.GOOS
	}
	if options.ActionCheckInterval <= 0 {
		options.ActionCheckInterval = time.Minute
	}
	if options.SnapshotInterval <= 0 {
		options.SnapshotInterval = 5 * time.Minute
	}
	if options.RetryInterval <= 0 {
		options.RetryInterval = 5 * time.Second
	}
	if options.CommandTimeout <= 0 {
		options.CommandTimeout = 5 * time.Second
	}
	if options.CleanupTimeout <= 0 {
		options.CleanupTimeout = 50 * time.Second
	}
	if options.Runner == nil {
		options.Runner = execCommandRunner{}
	}
	if options.FlowGuardPath == "" {
		if executable, err := os.Executable(); err == nil {
			options.FlowGuardPath = executable
		} else {
			options.FlowGuardPath = os.Args[0]
		}
	}
	return &Manager{
		options: options,
		wake:    make(chan struct{}, 1),
		events:  make(chan Event, 4096),
		done:    make(chan struct{}),
		initial: make(chan struct{}),
		jails:   make(map[string]*jailState),
	}
}

// Start launches synchronization and returns a channel that closes after the
// initial reconciliation attempt, or immediately when synchronization cannot
// run because the integration is disabled or the host is not Linux.
func (m *Manager) Start() <-chan struct{} {
	if !m.started.CompareAndSwap(false, true) {
		return m.initial
	}
	if !m.enabled.Load() || m.options.GOOS != "linux" {
		m.completeInitialAttempt()
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	go m.run(ctx)
	return m.initial
}

func (m *Manager) SetEnabled(enabled bool) {
	m.enabled.Store(enabled)
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *Manager) Stop() {
	if !m.started.CompareAndSwap(true, false) {
		m.clearState()
		m.completeInitialAttempt()
		return
	}
	m.cancel()
	<-m.done
}

func (m *Manager) completeInitialAttempt() {
	m.initOnce.Do(func() { close(m.initial) })
}

func (m *Manager) MatchingJails(rawIP string) []string {
	if !m.enabled.Load() {
		return nil
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		return nil
	}
	addr = addr.Unmap()

	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	matched := make([]string, 0)
	for jail, state := range m.jails {
		if state != nil && state.set.Contains(addr) {
			matched = append(matched, jail)
		}
	}
	sort.Strings(matched)
	return matched
}

func (m *Manager) run(ctx context.Context) {
	defer m.completeInitialAttempt()
	defer close(m.done)
	var server *eventServer
	var serverDone <-chan struct{}
	owned := make(map[string]struct{})
	cleanupPending := make(map[string]struct{})
	collisions := make(map[string]struct{})
	snapshotted := make(map[string]struct{})
	active := false
	available := false
	runtimeEventsUnavailable := false
	fullSyncNext := true
	var nextActionCheck time.Time
	var nextSnapshot time.Time
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	socketCheck := time.NewTicker(m.options.RetryInterval)
	defer socketCheck.Stop()

	cleanup := func() {
		if !active {
			return
		}
		m.clearState()
		server.close(m.options.EventSocketPath)
		server = nil
		serverDone = nil
		m.cleanupOwnedActions(owned, cleanupPending)
		clear(owned)
		clear(cleanupPending)
		clear(collisions)
		clear(snapshotted)
	drainEvents:
		for {
			select {
			case <-m.events:
				continue
			default:
				break drainEvents
			}
		}
		active = false
		available = false
		runtimeEventsUnavailable = false
		fullSyncNext = true
		nextActionCheck = time.Time{}
		nextSnapshot = time.Time{}
		log.Printf("[fail2ban] Integration stopped")
	}
	loseRuntimeServer := func(reason string) {
		if server == nil {
			return
		}
		server.close(m.options.EventSocketPath)
		server = nil
		serverDone = nil
		if !runtimeEventsUnavailable {
			log.Printf("[fail2ban] Runtime events unavailable: %s; using reconciliation only", reason)
		}
		runtimeEventsUnavailable = true
		resetTimer(timer, 0)
	}

	for {
		desired := m.enabled.Load() && m.options.GOOS == "linux"
		if desired && !active {
			active = true
			fullSyncNext = true
			resetTimer(timer, 0)
		} else if !desired && active {
			cleanup()
		}

		if !active {
			if !desired {
				m.completeInitialAttempt()
			}
			select {
			case <-ctx.Done():
				return
			case <-m.wake:
				if m.enabled.Load() && m.options.GOOS != "linux" {
					log.Printf("[fail2ban] Integration is only available on Linux")
				}
			}
			continue
		}

		select {
		case <-ctx.Done():
			cleanup()
			return
		case <-m.wake:
			continue
		case <-serverDone:
			loseRuntimeServer("event listener stopped")
			continue
		case <-socketCheck.C:
			if server != nil && !server.ownsSocketPath(m.options.EventSocketPath) {
				loseRuntimeServer("event socket path was removed or replaced")
			}
			continue
		case event := <-m.events:
			m.applyEvent(event)
		case <-timer.C:
			if server == nil {
				var serverErr error
				server, serverErr = startEventServer(m.options.EventSocketPath, m.events)
				if serverErr != nil {
					if !runtimeEventsUnavailable {
						log.Printf("[fail2ban] Runtime events unavailable: %v; using reconciliation only", serverErr)
					}
					runtimeEventsUnavailable = true
				} else if runtimeEventsUnavailable {
					log.Printf("[fail2ban] Runtime events restored")
					runtimeEventsUnavailable = false
				}
				if server != nil {
					serverDone = server.done
				}
			}

			controller, err := m.controller()
			if err != nil {
				available = false
				fullSyncNext = true
				log.Printf("[fail2ban] Integration unavailable; retaining last known bans: %v", err)
				m.completeInitialAttempt()
				resetTimer(timer, m.options.RetryInterval)
				continue
			}

			now := time.Now()
			fullSnapshot := fullSyncNext || nextSnapshot.IsZero() || !now.Before(nextSnapshot)
			nextAvailable, reconcileErr := m.reconcile(ctx, controller, server != nil, fullSnapshot, owned, cleanupPending, collisions, snapshotted)
			if reconcileErr != nil {
				alive, pingErr := controller.ping(ctx)
				switch {
				case pingErr == nil && alive:
					log.Printf("[fail2ban] Reconciliation failed; retaining last known bans: %v", reconcileErr)
				case isInconclusiveCommandError(pingErr):
					log.Printf("[fail2ban] Reconciliation was inconclusive; retaining last known bans: %v", reconcileErr)
				default:
					m.clearState()
					log.Printf("[fail2ban] Daemon unavailable; cleared synchronized bans: %v", reconcileErr)
				}
				available = false
				fullSyncNext = true
				m.completeInitialAttempt()
				resetTimer(timer, m.options.RetryInterval)
				continue
			}
			if !available && nextAvailable {
				log.Printf("[fail2ban] Synchronized %d active jail(s) with %d ban entries", m.jailCount(), m.entryCount())
			}
			available = nextAvailable
			fullSyncNext = false
			m.completeInitialAttempt()
			completedAt := time.Now()
			if fullSnapshot {
				nextSnapshot = completedAt.Add(m.options.SnapshotInterval)
			}
			nextActionCheck = completedAt.Add(m.options.ActionCheckInterval)
			nextDelay := nextSyncDelay(nextActionCheck, nextSnapshot)
			if server == nil && m.options.RetryInterval < nextDelay {
				nextDelay = m.options.RetryInterval
			}
			resetTimer(timer, nextDelay)
		}
	}
}

func (m *Manager) cleanupOwnedActions(owned, cleanupPending map[string]struct{}) {
	if len(owned) == 0 {
		return
	}
	controller, err := m.controller()
	if err != nil {
		log.Printf("[fail2ban] Failed to initialize runtime-action cleanup: %v", err)
		return
	}

	jails := make([]string, 0, len(owned))
	for jail := range owned {
		jails = append(jails, jail)
	}
	sort.Strings(jails)
	overallCtx, overallCancel := context.WithTimeout(context.Background(), m.options.CleanupTimeout)
	defer overallCancel()
	for index, jail := range jails {
		if overallCtx.Err() != nil {
			log.Printf("[fail2ban] Runtime-action cleanup deadline reached; %d jail(s) were not attempted", len(jails)-index)
			break
		}
		cleanupCtx, cancel := context.WithTimeout(overallCtx, m.options.CommandTimeout)
		var err error
		if _, pending := cleanupPending[jail]; pending {
			err = controller.removeKnownAction(cleanupCtx, jail)
		} else {
			err = controller.removeOwnedAction(cleanupCtx, jail)
		}
		cancel()
		if err != nil {
			log.Printf("[fail2ban] Failed to remove runtime action from jail %s: %v", jail, err)
		}
	}
}

func (m *Manager) controller() (*controller, error) {
	clientPath := m.options.ClientPath
	if clientPath == "" {
		var err error
		clientPath, err = exec.LookPath("fail2ban-client")
		if err != nil {
			return nil, fmt.Errorf("find fail2ban-client: %w", err)
		}
	}
	return &controller{
		clientPath:     clientPath,
		flowguardPath:  m.options.FlowGuardPath,
		runner:         m.options.Runner,
		commandTimeout: m.options.CommandTimeout,
	}, nil
}

func (m *Manager) reconcile(ctx context.Context, controller *controller, attachActions, fullSnapshot bool, owned, cleanupPending, collisions, snapshotted map[string]struct{}) (bool, error) {
	jails, err := controller.listJails(ctx)
	if err != nil {
		return false, err
	}
	activeJails := make(map[string]struct{}, len(jails))
	var reconcileErrors []error
	for _, jail := range jails {
		activeJails[jail] = struct{}{}
		action := actionUnavailable
		if attachActions {
			var actionErr error
			_, retryingCleanup := cleanupPending[jail]
			if retryingCleanup {
				actionErr = controller.removeKnownAction(ctx, jail)
				if actionErr == nil {
					delete(cleanupPending, jail)
					delete(owned, jail)
					action, actionErr = controller.ensureAction(ctx, jail)
				}
			} else if !fullSnapshot {
				_, wasOwned := owned[jail]
				_, wasCollision := collisions[jail]
				if wasOwned || wasCollision {
					var present bool
					present, actionErr = controller.hasAction(ctx, jail, runtimeActionName)
					if present {
						if wasOwned {
							action = actionOwned
						} else {
							action = actionCollision
						}
					} else if actionErr == nil {
						action, actionErr = controller.ensureAction(ctx, jail)
					}
				} else {
					action, actionErr = controller.ensureAction(ctx, jail)
				}
			} else {
				action, actionErr = controller.ensureAction(ctx, jail)
			}
			switch {
			case action == actionCleanupPending:
				owned[jail] = struct{}{}
				cleanupPending[jail] = struct{}{}
				delete(collisions, jail)
				log.Printf("[fail2ban] Failed to configure and clean up runtime action for jail %s: %v", jail, actionErr)
				reconcileErrors = append(reconcileErrors, fmt.Errorf("clean up partial runtime action for jail %q: %w", jail, actionErr))
			case actionErr != nil:
				log.Printf("[fail2ban] Failed to attach runtime action to jail %s: %v", jail, actionErr)
				if retryingCleanup {
					reconcileErrors = append(reconcileErrors, fmt.Errorf("retry runtime action cleanup for jail %q: %w", jail, actionErr))
				}
			case action == actionCollision:
				if _, logged := collisions[jail]; !logged {
					log.Printf("[fail2ban] Jail %s already has an unrelated %s action; using reconciliation only", jail, runtimeActionName)
					collisions[jail] = struct{}{}
				}
				delete(owned, jail)
			case action == actionOwned || action == actionAttached:
				owned[jail] = struct{}{}
				delete(cleanupPending, jail)
				delete(collisions, jail)
				if action == actionAttached {
					delete(snapshotted, jail)
				}
			}
		}

		_, hasSnapshot := snapshotted[jail]
		if !fullSnapshot && hasSnapshot {
			continue
		}
		prefixes, queryErr := controller.bannedPrefixes(ctx, jail)
		if queryErr != nil {
			log.Printf("[fail2ban] Failed to query bans for jail %s; retaining its last known state: %v", jail, queryErr)
			delete(snapshotted, jail)
			reconcileErrors = append(reconcileErrors, fmt.Errorf("query bans for jail %q: %w", jail, queryErr))
			continue
		}
		m.replaceJail(jail, prefixes)
		snapshotted[jail] = struct{}{}
	}

	m.stateMu.Lock()
	for jail := range m.jails {
		if _, ok := activeJails[jail]; !ok {
			delete(m.jails, jail)
		}
	}
	m.stateMu.Unlock()
	for jail := range owned {
		if _, ok := activeJails[jail]; !ok {
			delete(owned, jail)
		}
	}
	for jail := range collisions {
		if _, ok := activeJails[jail]; !ok {
			delete(collisions, jail)
		}
	}
	for jail := range cleanupPending {
		if _, ok := activeJails[jail]; !ok {
			delete(cleanupPending, jail)
		}
	}
	for jail := range snapshotted {
		if _, ok := activeJails[jail]; !ok {
			delete(snapshotted, jail)
		}
	}
	if len(reconcileErrors) > 0 {
		return false, errors.Join(reconcileErrors...)
	}
	return true, nil
}

func nextSyncDelay(actionCheck, snapshot time.Time) time.Duration {
	next := actionCheck
	if next.IsZero() || (!snapshot.IsZero() && snapshot.Before(next)) {
		next = snapshot
	}
	delay := time.Until(next)
	if delay < 0 {
		return 0
	}
	return delay
}

func (m *Manager) applyEvent(event Event) {
	if err := event.validate(); err != nil {
		return
	}
	prefix, _ := iplist.ParsePrefix(event.Address)

	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	state := m.jails[event.Jail]
	if state == nil {
		state = &jailState{prefixes: make(map[netip.Prefix]struct{})}
	}
	if event.Operation == "ban" {
		state.prefixes[prefix] = struct{}{}
	} else {
		delete(state.prefixes, prefix)
	}
	state.set = setFromPrefixMap(state.prefixes)
	m.jails[event.Jail] = state
}

func (m *Manager) replaceJail(jail string, values []string) {
	prefixes := make(map[netip.Prefix]struct{}, len(values))
	for _, value := range values {
		prefix, err := iplist.ParsePrefix(value)
		if err == nil {
			prefixes[prefix] = struct{}{}
		}
	}
	m.stateMu.Lock()
	m.jails[jail] = &jailState{prefixes: prefixes, set: setFromPrefixMap(prefixes)}
	m.stateMu.Unlock()
}

func setFromPrefixMap(values map[netip.Prefix]struct{}) *iplist.Set {
	prefixes := make([]netip.Prefix, 0, len(values))
	for prefix := range values {
		prefixes = append(prefixes, prefix)
	}
	return iplist.NewSet(prefixes)
}

func (m *Manager) clearState() {
	m.stateMu.Lock()
	m.jails = make(map[string]*jailState)
	m.stateMu.Unlock()
}

func (m *Manager) entryCount() int {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	count := 0
	for _, state := range m.jails {
		if state != nil {
			count += len(state.prefixes)
		}
	}
	return count
}

func (m *Manager) jailCount() int {
	m.stateMu.RLock()
	defer m.stateMu.RUnlock()
	return len(m.jails)
}

func resetTimer(timer *time.Timer, delay time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(delay)
}

type Inspection struct {
	Available bool
	Jails     []string
	Reason    string
}

func Inspect(ctx context.Context) Inspection {
	if runtime.GOOS != "linux" {
		return Inspection{Reason: "Fail2Ban integration is only available on Linux"}
	}
	path, err := exec.LookPath("fail2ban-client")
	if err != nil {
		return Inspection{Reason: "fail2ban-client was not found"}
	}
	controller := &controller{
		clientPath: path, flowguardPath: os.Args[0], runner: execCommandRunner{}, commandTimeout: 5 * time.Second,
	}
	jails, err := controller.listJails(ctx)
	if err != nil {
		return Inspection{Reason: err.Error()}
	}
	if len(jails) == 0 {
		return Inspection{Reason: "Fail2Ban has no active jails"}
	}
	return Inspection{Available: true, Jails: jails}
}
