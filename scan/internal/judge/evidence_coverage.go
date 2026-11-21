package judge

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"sort"
	"strings"
)

type evidenceCoverage struct {
	Role     string   `json:"role"`
	Required bool     `json:"required"`
	State    string   `json:"state"`
	Evidence []string `json:"evidence_refs"`
}

// augmentRoles exposes actual supplied code by semantic role across all adapters.
// It indexes evidence; it never invents a flow edge or discharges a blocker.
func augmentRoles(use analysis.CandidateUse, roles map[string][]string, ref func(analysis.Evidence) string) {
	add := func(role string, e analysis.Evidence) {
		id := ref(e)
		for _, existing := range roles[role] {
			if existing == id {
				return
			}
		}
		roles[role] = append(roles[role], id)
	}
	for _, e := range use.Context {
		role := ""
		switch e.Kind {
		case "handler", "invoked_callable":
			role = "invoked_callable"
		case "helper_definition", "relevant_function", "condition_helper", "wrapper_definition", "authentication_adapter":
			role = "helper_definitions"
		case "branch_precondition", "branch_true_precondition", "branch_false_precondition", "branch_alternative", "guard_test", "conditional_test", "conditional_false_test", "exception_precondition", "condition":
			role = "path_conditions"
		case "form_field_requirement", "field_policy":
			role = "field_policy"
		case "render_markup_context":
			role = "render_context"
		case "sink_binding", "logger_binding", "render_binding":
			role = e.Kind
		case "receiver_binding", "route_registration":
			role = "entry_binding"
		case "call_binding", "argument_to_parameter", "helper_return":
			role = "call_bindings"
		}
		if role != "" {
			add(role, e)
		}
	}
	for _, d := range use.Dependencies {
		add(d.Source.Kind, d.Source)
		for _, e := range d.Transfers {
			add("value_transfers", e)
			if strings.Contains(e.Kind, "guard") || strings.Contains(e.Kind, "condition") {
				add("path_conditions", e)
			}
		}
	}
}
func coverageLedger(required []string, roles map[string][]string) []evidenceCoverage {
	needed := map[string]bool{}
	keys := map[string]bool{}
	for _, role := range required {
		needed[role] = true
		keys[role] = true
	}
	for role := range roles {
		keys[role] = true
	}
	ordered := []string{}
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	result := []evidenceCoverage{}
	for _, role := range ordered {
		state := "supplied"
		if len(roles[role]) == 0 {
			state = "missing"
		}
		result = append(result, evidenceCoverage{role, needed[role], state, append([]string{}, roles[role]...)})
	}
	return result
}
