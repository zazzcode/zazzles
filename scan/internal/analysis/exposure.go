package analysis

import "fmt"

// ExposureKind is the claim kind of a diagnostic operation whose output is
// internal state, reachable from an entry (CWE-200, CWE-215).
const ExposureKind = "info_exposure_candidate"

// Exposure subjects name what the recorded operation reveals.
const (
	ExposureConfiguration = "configuration"
	ExposureEnvironment   = "environment"
	ExposureRuntimeState  = "runtime_state"
	ExposureStack         = "stack"
)

// ExposureEnvironmentDependent is the gap of a framework dump whose output
// depends on the debug environment.
const ExposureEnvironmentDependent = "diagnostic_output_environment_dependent"

// ExposureFacts records a diagnostic operation, what it reveals, its entry and
// the conditions that dominate it. Guards are evidence, not a filter (D-2).
type ExposureFacts struct {
	Operation   string     `json:"operation"`
	Subject     string     `json:"subject"`
	Flag        string     `json:"flag,omitempty"`
	EntryServed string     `json:"entry_served"`
	Guards      []Evidence `json:"guards,omitempty"`
}

// Validate rejects a record whose operation, subject or entry fact is outside
// the closed lists.
func (f *ExposureFacts) Validate() error {
	if f == nil || f.Operation == "" {
		return fmt.Errorf("missing exposure operation")
	}
	switch f.Subject {
	case ExposureConfiguration, ExposureEnvironment, ExposureRuntimeState, ExposureStack:
	default:
		return fmt.Errorf("invalid exposure subject")
	}
	switch f.EntryServed {
	case "yes", "no", "unresolved":
	default:
		return fmt.Errorf("invalid exposure entry_served")
	}
	for _, g := range f.Guards {
		if g.Kind == "" || g.Span.File == "" {
			return fmt.Errorf("invalid exposure guard evidence")
		}
	}
	return nil
}
