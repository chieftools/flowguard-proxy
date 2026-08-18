package fail2ban

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"flowguard/iplist"
)

const runtimeActionName = "flowguard-runtime"

type commandRunner interface {
	CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execCommandRunner struct{}

func (execCommandRunner) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type controller struct {
	clientPath     string
	flowguardPath  string
	runner         commandRunner
	commandTimeout time.Duration
}

func (c *controller) command(ctx context.Context, args ...string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, c.commandTimeout)
	defer cancel()

	output, err := c.runner.CombinedOutput(commandCtx, c.clientPath, args...)
	text := strings.TrimSpace(string(output))
	if err != nil {
		if commandCtx.Err() != nil {
			return "", fmt.Errorf("fail2ban-client %s: %w", strings.Join(args, " "), commandCtx.Err())
		}
		if text == "" {
			return "", fmt.Errorf("fail2ban-client %s: %w", strings.Join(args, " "), err)
		}
		return "", fmt.Errorf("fail2ban-client %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return text, nil
}

func (c *controller) listJails(ctx context.Context) ([]string, error) {
	output, err := c.command(ctx, "status")
	if err != nil {
		return nil, err
	}
	return parseJailList(output)
}

func parseJailList(output string) ([]string, error) {
	for _, line := range strings.Split(output, "\n") {
		marker := strings.Index(line, "Jail list:")
		if marker < 0 {
			continue
		}

		value := strings.TrimSpace(line[marker+len("Jail list:"):])
		if value == "" {
			return nil, nil
		}

		seen := make(map[string]struct{})
		jails := make([]string, 0)
		for _, raw := range strings.Split(value, ",") {
			jail := strings.TrimSpace(raw)
			if jail == "" {
				continue
			}
			if _, ok := seen[jail]; ok {
				continue
			}
			seen[jail] = struct{}{}
			jails = append(jails, jail)
		}
		sort.Strings(jails)
		return jails, nil
	}
	return nil, fmt.Errorf("fail2ban status did not contain a jail list")
}

func (c *controller) bannedPrefixes(ctx context.Context, jail string) ([]string, error) {
	output, err := c.command(ctx, "get", jail, "banip")
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	values := make([]string, 0)
	for _, raw := range strings.Fields(output) {
		prefix, parseErr := iplist.ParsePrefix(raw)
		if parseErr != nil {
			return nil, fmt.Errorf("parse banned address %q for jail %q: %w", raw, jail, parseErr)
		}
		canonical := prefix.String()
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		values = append(values, canonical)
	}
	sort.Strings(values)
	return values, nil
}

type actionStatus int

const (
	actionUnavailable actionStatus = iota
	actionOwned
	actionAttached
	actionCleanupPending
	actionCollision
)

func (c *controller) ensureAction(ctx context.Context, jail string) (actionStatus, error) {
	banCommand := c.actionCommand("ban", jail)
	unbanCommand := c.actionCommand("unban", jail)

	existingBan, banErr := c.command(ctx, "get", jail, "action", runtimeActionName, "actionban")
	if banErr == nil {
		existingUnban, unbanErr := c.command(ctx, "get", jail, "action", runtimeActionName, "actionunban")
		if unbanErr != nil {
			return actionUnavailable, unbanErr
		}
		if existingBan != banCommand || existingUnban != unbanCommand {
			return actionCollision, nil
		}
		return actionOwned, nil
	}

	if _, err := c.command(ctx, "set", jail, "addaction", runtimeActionName); err != nil {
		return actionUnavailable, err
	}

	for _, property := range []struct {
		name  string
		value string
	}{
		{name: "actionban", value: banCommand},
		{name: "actionunban", value: unbanCommand},
		{name: "timeout", value: "1"},
	} {
		if _, err := c.command(ctx, "set", jail, "action", runtimeActionName, property.name, property.value); err != nil {
			configureErr := fmt.Errorf("configure runtime action property %q for jail %q: %w", property.name, jail, err)
			if cleanupErr := c.removeKnownAction(context.Background(), jail); cleanupErr != nil {
				return actionCleanupPending, errors.Join(
					configureErr,
					fmt.Errorf("clean up partially configured runtime action for jail %q: %w", jail, cleanupErr),
				)
			}
			return actionUnavailable, configureErr
		}
	}
	return actionAttached, nil
}

// removeKnownAction removes an action that this process knows it created. If
// deletion reports an error, a follow-up action listing distinguishes a
// completed/disappeared action from a cleanup that still needs to be retried.
func (c *controller) removeKnownAction(ctx context.Context, jail string) error {
	_, removeErr := c.command(ctx, "set", jail, "delaction", runtimeActionName)
	if removeErr == nil {
		return nil
	}

	present, confirmErr := c.hasAction(ctx, jail, runtimeActionName)
	if confirmErr != nil {
		return errors.Join(removeErr, fmt.Errorf("confirm runtime action cleanup for jail %q: %w", jail, confirmErr))
	}
	if !present {
		return nil
	}
	return removeErr
}

func (c *controller) removeOwnedAction(ctx context.Context, jail string) error {
	present, err := c.hasAction(ctx, jail, runtimeActionName)
	if err != nil {
		return fmt.Errorf("query actions for jail %q before cleanup: %w", jail, err)
	}
	if !present {
		return nil
	}

	banCommand, err := c.command(ctx, "get", jail, "action", runtimeActionName, "actionban")
	if err != nil {
		return c.confirmMissingAction(ctx, jail, fmt.Errorf("query ban command for jail %q: %w", jail, err))
	}
	unbanCommand, err := c.command(ctx, "get", jail, "action", runtimeActionName, "actionunban")
	if err != nil {
		return c.confirmMissingAction(ctx, jail, fmt.Errorf("query unban command for jail %q: %w", jail, err))
	}
	if banCommand != c.actionCommand("ban", jail) || unbanCommand != c.actionCommand("unban", jail) {
		return nil
	}
	_, err = c.command(ctx, "set", jail, "delaction", runtimeActionName)
	return err
}

func (c *controller) hasAction(ctx context.Context, jail, action string) (bool, error) {
	output, err := c.command(ctx, "get", jail, "actions")
	if err != nil {
		return false, err
	}
	for _, token := range strings.FieldsFunc(output, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.')
	}) {
		if token == action {
			return true, nil
		}
	}
	return false, nil
}

func (c *controller) confirmMissingAction(ctx context.Context, jail string, queryErr error) error {
	present, confirmErr := c.hasAction(ctx, jail, runtimeActionName)
	if confirmErr != nil {
		return errors.Join(queryErr, fmt.Errorf("confirm runtime action for jail %q: %w", jail, confirmErr))
	}
	if !present {
		return nil
	}
	return queryErr
}

func (c *controller) ping(ctx context.Context) (bool, error) {
	output, err := c.command(ctx, "ping")
	if err != nil {
		return false, err
	}
	return strings.Contains(strings.ToLower(output), "pong"), nil
}

func (c *controller) actionCommand(operation, jail string) string {
	return strings.Join([]string{
		shellQuote(c.flowguardPath),
		"fail2ban-event",
		shellQuote(operation),
		shellQuote(jail),
		"'<ip>'",
	}, " ")
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func isInconclusiveCommandError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var pathError *os.PathError
	if errors.As(err, &pathError) {
		return true
	}
	var execError *exec.Error
	return errors.As(err, &execError)
}
