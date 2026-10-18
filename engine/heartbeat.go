package engine

import (
	"context"
	"log"
	"math/rand/v2"
	"runtime"
	"time"

	"go.chief.tools/flowguard-proxy/api"
	"go.chief.tools/flowguard-proxy/instance"
	"go.chief.tools/flowguard-proxy/logger"
)

// heartbeatStopTimeout bounds the stop notification sent on shutdown.
const heartbeatStopTimeout = 2 * time.Second

// HeartbeatDetails holds the heartbeat fields that depend on how the host
// receives traffic.
type HeartbeatDetails struct {
	// Capabilities are reported in addition to the engine's own.
	Capabilities  []string
	Firewall      api.FirewallHeartbeat
	HostnameCount int
	BindAddresses []string
}

// RequestHeartbeat sends a heartbeat as soon as possible, for example after
// the host's firewall state changed.
func (e *Engine) RequestHeartbeat() {
	select {
	case e.forceHeartbeat <- struct{}{}:
	default:
	}
}

func (e *Engine) runHeartbeat() {
	// Read heartbeat config defaults
	const defaultInterval = 300 // 5 minutes
	const defaultJitter = 30    // 30 seconds

	getConfig := func() (enabled bool, interval, jitter int) {
		hbCfg := e.configManager.GetConfig().Heartbeat

		enabled = true
		interval = defaultInterval
		jitter = defaultJitter

		if hbCfg != nil {
			if hbCfg.Enabled != nil {
				enabled = *hbCfg.Enabled
			}
			if hbCfg.IntervalSeconds > 0 {
				interval = hbCfg.IntervalSeconds
			}
			if hbCfg.JitterSeconds > 0 {
				jitter = hbCfg.JitterSeconds
			}
		}

		return
	}

	enabled, _, _ := getConfig()
	if !enabled {
		if e.options.Verbose {
			log.Println("[heartbeat] Disabled by configuration")
		}
		// Still listen for stop signal, but also re-check config each default interval
		// in case it gets re-enabled
		for {
			timer := time.NewTimer(time.Duration(defaultInterval) * time.Second)
			select {
			case <-e.stopHeartbeat:
				timer.Stop()
				return
			case <-e.forceHeartbeat:
				timer.Stop()
				continue
			case <-timer.C:
				enabled, _, _ = getConfig()
				if enabled {
					log.Println("[heartbeat] Re-enabled by configuration")
					break
				}
				continue
			}
			break
		}
	}

	if e.options.Verbose {
		log.Println("[heartbeat] Started")
	}

	// Send immediately on startup
	e.sendHeartbeat()

	for {
		enabled, interval, jitter := getConfig()
		if !enabled {
			if e.options.Verbose {
				log.Println("[heartbeat] Disabled by configuration, pausing")
			}
			// Wait until re-enabled or stopped
			timer := time.NewTimer(time.Duration(defaultInterval) * time.Second)
			select {
			case <-e.stopHeartbeat:
				timer.Stop()
				if e.options.Verbose {
					log.Println("[heartbeat] Stopped")
				}
				return
			case <-e.forceHeartbeat:
				timer.Stop()
				continue
			case <-timer.C:
				continue
			}
		}

		// Apply jitter: interval +/- jitter (uniform random)
		jitteredInterval := interval
		if jitter > 0 {
			jitteredInterval += rand.IntN(2*jitter+1) - jitter
		}
		if jitteredInterval < 1 {
			jitteredInterval = 1
		}

		timer := time.NewTimer(time.Duration(jitteredInterval) * time.Second)
		select {
		case <-e.stopHeartbeat:
			timer.Stop()
			if e.options.Verbose {
				log.Println("[heartbeat] Stopped")
			}
			return
		case <-e.forceHeartbeat:
			timer.Stop()
			e.sendHeartbeat()
		case <-timer.C:
			e.sendHeartbeat()
		}
	}
}

func (e *Engine) heartbeatPayload() api.HeartbeatPayload {
	var details HeartbeatDetails
	if e.options.Heartbeat != nil {
		details = e.options.Heartbeat()
	}

	// Older panels require a list, so never send null
	bindAddresses := details.BindAddresses
	if bindAddresses == nil {
		bindAddresses = []string{}
	}

	return api.HeartbeatPayload{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Version:       e.options.Version,
		Capabilities:  append([]string{logger.FlowGuardIngestCapability}, details.Capabilities...),
		Hostname:      instance.Hostname(),
		Region:        instance.Region(),
		Firewall:      details.Firewall,
		StartedAt:     e.startedAt.Unix(),
		HostnameCount: details.HostnameCount,
		BindAddresses: bindAddresses,
	}
}

// sendHeartbeatStop tells the panel this instance stopped. It is best effort and
// bounded, so an unreachable panel never delays shutdown for long.
func (e *Engine) sendHeartbeatStop() {
	ctx, cancel := context.WithTimeout(context.Background(), heartbeatStopTimeout)
	defer cancel()

	if err := e.configManager.GetAPIClient().SendHeartbeatStop(ctx); err != nil {
		log.Printf("[heartbeat] Failed to send stop: %v", err)
		return
	}

	if e.options.Verbose {
		log.Println("[heartbeat] Sent stop")
	}
}

func (e *Engine) sendHeartbeat() {
	if err := e.configManager.GetAPIClient().SendHeartbeat(e.heartbeatPayload()); err != nil {
		log.Printf("[heartbeat] Failed to send: %v", err)
		return
	}

	if e.options.Verbose {
		log.Println("[heartbeat] Sent successfully")
	}
}
