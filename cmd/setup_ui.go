package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"charm.land/huh/v2"
)

type setupInteractionMode uint8

const (
	setupInteractionPlain setupInteractionMode = iota
	setupInteractionTUI
	setupInteractionAccessible
)

var (
	setupLookupEnvironment  = os.LookupEnv
	setupStreamsAreTerminal = func() bool {
		input, inputOK := setupInput.(*os.File)
		output, outputOK := setupOutput.(*os.File)
		return inputOK && outputOK && isTerminal(input) && isTerminal(output)
	}
	setupRunForm = func(form *huh.Form) error {
		return form.Run()
	}
)

func resolveSetupInteractionMode(disabled, disabledByEnvironment, accessible, terminalStreams bool, term string) setupInteractionMode {
	if disabled || disabledByEnvironment {
		return setupInteractionPlain
	}
	if accessible {
		return setupInteractionAccessible
	}
	if terminalStreams && !strings.EqualFold(term, "dumb") {
		return setupInteractionTUI
	}
	return setupInteractionPlain
}

func currentSetupInteractionMode() setupInteractionMode {
	return resolveSetupInteractionMode(
		noTUI,
		environmentValueIsSet("FLOWGUARD_NO_TUI"),
		environmentValueIsSet("ACCESSIBLE"),
		setupStreamsAreTerminal(),
		setupEnvironmentValue("TERM"),
	)
}

func environmentValueIsSet(name string) bool {
	value, ok := setupLookupEnvironment(name)
	return ok && value != ""
}

func setupEnvironmentValue(name string) string {
	value, _ := setupLookupEnvironment(name)
	return value
}

func promptYesNo(reader *bufio.Reader, output io.Writer, question string, defaultYes bool) (bool, error) {
	if currentSetupInteractionMode() == setupInteractionPlain {
		return promptYesNoPlain(reader, output, question, defaultYes)
	}

	value := defaultYes
	form := newSetupForm(huh.NewGroup(
		huh.NewConfirm().Title(question).Value(&value),
	))
	if err := runSetupForm(form, reader, output); err != nil {
		return false, err
	}
	return value, nil
}

func promptChoice(reader *bufio.Reader, output io.Writer, question string, options []string, defaultIndex int) (int, error) {
	if len(options) == 0 || defaultIndex < 0 || defaultIndex >= len(options) {
		return 0, fmt.Errorf("invalid choice options")
	}
	if currentSetupInteractionMode() == setupInteractionPlain {
		return promptChoicePlain(reader, output, question, options, defaultIndex)
	}

	selected := defaultIndex
	huhOptions := make([]huh.Option[int], 0, len(options))
	for index, option := range options {
		huhOptions = append(huhOptions, huh.NewOption(option, index))
	}
	form := newSetupForm(huh.NewGroup(
		huh.NewSelect[int]().Title(question).Options(huhOptions...).Value(&selected),
	))
	if err := runSetupForm(form, reader, output); err != nil {
		return 0, err
	}
	return selected, nil
}

func promptCheckboxes(reader *bufio.Reader, output io.Writer, title string, labels []string, defaults []bool, requireOne bool) ([]bool, error) {
	if len(labels) == 0 || len(labels) != len(defaults) {
		return nil, fmt.Errorf("invalid checkbox options")
	}
	if currentSetupInteractionMode() == setupInteractionPlain {
		return promptCheckboxesPlain(reader, output, title, labels, defaults, requireOne)
	}

	selected := make([]int, 0, len(defaults))
	options := make([]huh.Option[int], 0, len(labels))
	for index, label := range labels {
		options = append(options, huh.NewOption(label, index))
		if defaults[index] {
			selected = append(selected, index)
		}
	}
	field := huh.NewMultiSelect[int]().Title(title).Options(options...).Value(&selected)
	if requireOne {
		field.Validate(func(values []int) error {
			if len(values) == 0 {
				return fmt.Errorf("at least one option must be selected")
			}
			return nil
		})
	}
	form := newSetupForm(huh.NewGroup(field))
	if err := runSetupForm(form, reader, output); err != nil {
		return nil, err
	}

	result := make([]bool, len(labels))
	for _, index := range selected {
		if index >= 0 && index < len(result) {
			result[index] = true
		}
	}
	return result, nil
}

func newSetupForm(groups ...*huh.Group) *huh.Form {
	return huh.NewForm(groups...).WithShowHelp(true).WithShowErrors(true)
}

func runSetupForm(form *huh.Form, reader *bufio.Reader, output io.Writer) error {
	mode := currentSetupInteractionMode()
	input := io.Reader(reader)
	if mode == setupInteractionTUI {
		input = setupInput
	}
	form.WithInput(input).WithOutput(output).WithAccessible(mode == setupInteractionAccessible)
	if err := setupRunForm(form); err != nil {
		if errors.Is(err, huh.ErrUserAborted) {
			return fmt.Errorf("setup canceled: %w", err)
		}
		return fmt.Errorf("interactive form failed: %w; retry with --no-tui", err)
	}
	return nil
}

func runSetupSpinner(title string, action func() error) error {
	mode := currentSetupInteractionMode()
	if mode == setupInteractionAccessible {
		fmt.Fprintf(setupOutput, "%s...\n", title)
		return action()
	}

	result := make(chan error, 1)
	go func() {
		result <- action()
	}()

	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	index := 0
	for {
		fmt.Fprintf(setupOutput, "\r\033[2K%s %s...", frames[index%len(frames)], title)
		index++

		select {
		case err := <-result:
			fmt.Fprint(setupOutput, "\r\033[2K")
			return err
		case <-ticker.C:
		}
	}
}
