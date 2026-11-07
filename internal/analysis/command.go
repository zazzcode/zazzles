package analysis

import "fmt"

// Command operand slots. Shell text, executable choice, each argv element,
// shell configuration and executable overrides are separate claim slots.
const (
	CommandSlotShell      = "shell_command"
	CommandSlotExecutable = "executable"
	CommandSlotOption     = "shell_option"
	CommandSlotOverride   = "executable_override"
	// CommandSlotArgumentPrefix is followed by the zero-based argv index.
	CommandSlotArgumentPrefix = "argument:"
	CommandSlotArgvUnknown    = "argument:*"
)

// CommandFacts describes one process-execution use independently of language.
// Parser adapters establish every field from source; judgment and report code
// never infer them. Dependency indices refer to CandidateUse.Dependencies and
// context indices refer to CandidateUse.Context, so no second source store exists.
type CommandFacts struct {
	Operation  string `json:"operation"`
	ContractID string `json:"contract_id"`
	// Platform is a declared analysis assumption ("posix"), never inferred from the scanner host.
	Platform string `json:"platform"`
	// APIShellMode is the shell option of the called API; EffectiveShellMode
	// additionally accounts for a literal interpreter such as sh -c.
	APIShellMode       string `json:"api_shell_mode"`
	EffectiveShellMode string `json:"effective_shell_mode"`
	Interpreter        string `json:"interpreter,omitempty"`
	// ArgvShape is none, literal_list or unknown.
	ArgvShape string           `json:"argv_shape"`
	Operands  []CommandOperand `json:"operands"`
	Paths     []CommandPath    `json:"paths"`
}

// CommandOperand is one effective operand slot of the invocation.
type CommandOperand struct {
	Slot string `json:"slot"`
	// Dependencies indexes CandidateUse.Dependencies reaching this slot.
	Dependencies []int `json:"dependencies,omitempty"`
	// Context indexes constant/configuration evidence in CandidateUse.Context.
	Context  []int  `json:"context,omitempty"`
	Constant string `json:"constant,omitempty"`
	Dynamic  bool   `json:"dynamic,omitempty"`
}

// CommandPath is one source-to-operand path. Raw paths reach the slot without a
// source-backed control; guarded paths name a dominating or enclosing guard
// (its adequacy is judged separately, never assumed); an unknown path has
// unresolved transfer or guard facts. No global safe bit exists.
type CommandPath struct {
	Dependency int    `json:"dependency"`
	Operand    string `json:"operand"`
	Protection string `json:"protection"`
	Controls   []int  `json:"controls,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// Validate checks every index and enumerated value against the candidate use.
func (c *CommandFacts) Validate(deps, context int) error {
	if c == nil {
		return nil
	}
	switch c.Platform {
	case "posix":
	default:
		return fmt.Errorf("unsupported command platform assumption %q", c.Platform)
	}
	for _, mode := range []string{c.APIShellMode, c.EffectiveShellMode} {
		switch mode {
		case "enabled", "disabled", "unknown":
		default:
			return fmt.Errorf("invalid command shell mode %q", mode)
		}
	}
	switch c.ArgvShape {
	case "none", "literal_list", "unknown":
	default:
		return fmt.Errorf("invalid command argv shape %q", c.ArgvShape)
	}
	slots := map[string]bool{}
	for _, o := range c.Operands {
		if o.Slot == "" || slots[o.Slot] {
			return fmt.Errorf("invalid or duplicate command operand slot %q", o.Slot)
		}
		slots[o.Slot] = true
		for _, i := range o.Dependencies {
			if i < 0 || i >= deps {
				return fmt.Errorf("command operand %s dependency %d out of range", o.Slot, i)
			}
		}
		for _, i := range o.Context {
			if i < 0 || i >= context {
				return fmt.Errorf("command operand %s context %d out of range", o.Slot, i)
			}
		}
	}
	for _, p := range c.Paths {
		if p.Dependency < 0 || p.Dependency >= deps || !slots[p.Operand] {
			return fmt.Errorf("command path references missing dependency or operand")
		}
		switch p.Protection {
		case "raw", "guarded", "unknown":
		default:
			return fmt.Errorf("invalid command path protection %q", p.Protection)
		}
		for _, i := range p.Controls {
			if i < 0 || i >= context {
				return fmt.Errorf("command path control %d out of range", i)
			}
		}
	}
	return nil
}
