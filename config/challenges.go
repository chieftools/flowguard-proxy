package config

import "fmt"

const (
	ChallengeTypePoW = "pow"

	PoWAlgorithmPBKDF2SHA256 = "pbkdf2-sha256"
	PoWAlgorithmSHA256       = "sha256"

	PoWEffortModeCalibrated    = "calibrated"
	PoWEffortModeProbabilistic = "probabilistic"

	ChallengeScopeRule = "rule"
	ChallengeScopeHost = "host"
)

func validateChallengesConfig(cfg *Config) error {
	if cfg == nil {
		return nil
	}

	if cfg.Challenges != nil {
		if err := validateChallengeDefaults(cfg.Challenges); err != nil {
			return err
		}
	}

	for id, action := range cfg.Actions {
		if action == nil || action.Action != "challenge" {
			continue
		}

		if err := validateChallengeAction(id, action.Challenge); err != nil {
			return err
		}
	}

	return nil
}

func validateChallengeDefaults(challenges *ChallengesConfig) error {
	if challenges.DefaultTTLSeconds != nil && *challenges.DefaultTTLSeconds < 0 {
		return fmt.Errorf("challenges.default_ttl_seconds must be greater than or equal to 0")
	}
	if err := validateChallengeMinPageTime("challenges.min_page_time_ms", challenges.MinPageTimeMs); err != nil {
		return err
	}
	if challenges.PoW != nil {
		if challenges.PoW.ChallengeTTLSeconds != nil && *challenges.PoW.ChallengeTTLSeconds < 1 {
			return fmt.Errorf("challenges.pow.challenge_ttl_seconds must be greater than 0")
		}
		if err := validateChallengeDifficulty("challenges.pow.difficulty_bits", challenges.PoW.DifficultyBits); err != nil {
			return err
		}
		if err := validatePoWAlgorithm("challenges.pow.algorithm", challenges.PoW.Algorithm); err != nil {
			return err
		}
		if err := validatePBKDF2Iterations("challenges.pow.pbkdf2_iterations", challenges.PoW.PBKDF2Iterations); err != nil {
			return err
		}
		if err := validatePoWEffortMode("challenges.pow.effort_mode", challenges.PoW.EffortMode); err != nil {
			return err
		}
		if err := validatePoWWorkUnits("challenges.pow.work_units", challenges.PoW.WorkUnits); err != nil {
			return err
		}
	}
	if challenges.NonHTMLStatus != 0 && (challenges.NonHTMLStatus < 100 || challenges.NonHTMLStatus > 599) {
		return fmt.Errorf("challenges.non_html_status must be between 100 and 599")
	}
	if challenges.MaxAttemptsPerWindow != nil && *challenges.MaxAttemptsPerWindow < 0 {
		return fmt.Errorf("challenges.max_attempts_per_window must be greater than or equal to 0")
	}
	if challenges.AttemptWindowSeconds != nil && *challenges.AttemptWindowSeconds < 1 {
		return fmt.Errorf("challenges.attempt_window_seconds must be greater than 0")
	}
	return nil
}

func validateChallengeAction(actionID string, challenge *RuleActionChallengeConfig) error {
	if challenge == nil {
		return nil
	}

	if challenge.Type != "" && challenge.Type != ChallengeTypePoW {
		return fmt.Errorf("invalid challenge.type %q in action %q", challenge.Type, actionID)
	}

	switch challenge.ClearanceScope {
	case "", ChallengeScopeRule, ChallengeScopeHost:
	default:
		return fmt.Errorf("invalid challenge.clearance_scope %q in action %q", challenge.ClearanceScope, actionID)
	}

	if challenge.TTLSeconds != nil && *challenge.TTLSeconds < 0 {
		return fmt.Errorf("challenge.ttl_seconds in action %q must be greater than or equal to 0", actionID)
	}
	if err := validateChallengeMinPageTime(fmt.Sprintf("challenge.min_page_time_ms in action %q", actionID), challenge.MinPageTimeMs); err != nil {
		return err
	}

	if err := validateChallengeDifficulty(fmt.Sprintf("challenge.difficulty_bits in action %q", actionID), challenge.DifficultyBits); err != nil {
		return err
	}
	if err := validatePoWAlgorithm(fmt.Sprintf("challenge.algorithm in action %q", actionID), challenge.Algorithm); err != nil {
		return err
	}
	if err := validatePBKDF2Iterations(fmt.Sprintf("challenge.pbkdf2_iterations in action %q", actionID), challenge.PBKDF2Iterations); err != nil {
		return err
	}
	if err := validatePoWEffortMode(fmt.Sprintf("challenge.effort_mode in action %q", actionID), challenge.EffortMode); err != nil {
		return err
	}
	return validatePoWWorkUnits(fmt.Sprintf("challenge.work_units in action %q", actionID), challenge.WorkUnits)
}

func validateChallengeMinPageTime(field string, ms *int) error {
	if ms == nil {
		return nil
	}
	if *ms < 0 || *ms > 60000 {
		return fmt.Errorf("%s must be between 0 and 60000", field)
	}
	return nil
}

func validateChallengeDifficulty(field string, difficulty int) error {
	if difficulty == 0 {
		return nil
	}
	if difficulty < 1 || difficulty > 30 {
		return fmt.Errorf("%s must be between 1 and 30", field)
	}
	return nil
}

func validatePoWAlgorithm(field string, algorithm string) error {
	switch algorithm {
	case "", PoWAlgorithmPBKDF2SHA256, PoWAlgorithmSHA256:
		return nil
	default:
		return fmt.Errorf("%s must be %q or %q", field, PoWAlgorithmPBKDF2SHA256, PoWAlgorithmSHA256)
	}
}

func validatePBKDF2Iterations(field string, iterations int) error {
	if iterations == 0 {
		return nil
	}
	if iterations < 1 || iterations > 100000 {
		return fmt.Errorf("%s must be between 1 and 100000", field)
	}
	return nil
}

func validatePoWEffortMode(field string, mode string) error {
	switch mode {
	case "", PoWEffortModeCalibrated, PoWEffortModeProbabilistic:
		return nil
	default:
		return fmt.Errorf("%s must be %q or %q", field, PoWEffortModeCalibrated, PoWEffortModeProbabilistic)
	}
}

func validatePoWWorkUnits(field string, units int) error {
	if units == 0 {
		return nil
	}
	if units < 1 || units > 100000 {
		return fmt.Errorf("%s must be between 1 and 100000", field)
	}
	return nil
}
