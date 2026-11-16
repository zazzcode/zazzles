package analysis

import "fmt"

// CodeFacts records verified interpreter operands and their independent paths.
type CodeFacts struct {
	Operation        string        `json:"operation"`
	ContractID       string        `json:"contract_id"`
	Constraint       string        `json:"constraint,omitempty"`
	Shape            string        `json:"shape,omitempty"`
	ExecutionContext string        `json:"execution_context"`
	Paths            []CommandPath `json:"paths"`
}

// RedirectFacts records request-derived navigation destinations.
type RedirectFacts struct {
	Operation         string        `json:"operation"`
	ContractID        string        `json:"contract_id"`
	DestinationOrigin string        `json:"destination_origin"`
	Paths             []CommandPath `json:"paths"`
	// RelatedUse links another claim about this same navigation (usually XSS).
	RelatedUse string `json:"related_use,omitempty"`
}

// CodePaths returns the operand paths of an interpreter or redirect claim.
func (u CandidateUse) CodePaths() []CommandPath {
	if u.Code != nil {
		return u.Code.Paths
	}
	if u.Redirect != nil {
		return u.Redirect.Paths
	}
	return nil
}

// Validate checks interpreter path references and the execution context.
func (c *CodeFacts) Validate(deps, context int) error {
	if c == nil {
		return nil
	}
	if c.Operation == "" || c.ContractID == "" || c.ExecutionContext != "server" && c.ExecutionContext != "browser" {
		return fmt.Errorf("invalid interpreter operation or context")
	}
	return validateInterpreterPaths(c.Paths, "code", deps, context)
}

// Validate checks redirect path references and request destination provenance.
func (r *RedirectFacts) Validate(deps, context int) error {
	if r == nil {
		return nil
	}
	if r.Operation == "" || r.ContractID == "" || r.DestinationOrigin != DestinationRequest {
		return fmt.Errorf("invalid redirect operation or destination origin")
	}
	return validateInterpreterPaths(r.Paths, "destination", deps, context)
}

func validateInterpreterPaths(paths []CommandPath, slot string, deps, context int) error {
	seen := map[int]bool{}
	for _, p := range paths {
		if p.Dependency < 0 || p.Dependency >= deps || p.Operand != slot || seen[p.Dependency] {
			return fmt.Errorf("invalid or duplicate operand path")
		}
		seen[p.Dependency] = true
		if p.Protection != "raw" && p.Protection != "guarded" && p.Protection != "unknown" {
			return fmt.Errorf("invalid operand protection")
		}
		if p.Protection == "guarded" && len(p.Controls) == 0 {
			return fmt.Errorf("guarded path has no control")
		}
		for _, i := range p.Controls {
			if i < 0 || i >= context {
				return fmt.Errorf("invalid operand control index")
			}
		}
	}
	if len(seen) != deps || deps == 0 {
		return fmt.Errorf("operand paths do not cover every dependency")
	}
	return nil
}
