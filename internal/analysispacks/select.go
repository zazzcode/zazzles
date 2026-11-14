package analysispacks

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/lang"
)

// Select resolves scanner interpretation from existing verified source facts.
// It does not infer a library from a package declaration, name, or source text.
// Candidate kinds without a registered family keep their existing runtime
// paths and are rejected here rather than trusted to generic judgment.
func Select(use analysis.CandidateUse) (*analysis.ComponentSelection, error) {
	if err := Validate(); err != nil {
		return nil, err
	}
	return embedded.selectUse(use)
}

func (c *catalog) selectUse(use analysis.CandidateUse) (*analysis.ComponentSelection, error) {
	family := FamFamily(use.Kind)
	if family == nil {
		return nil, fmt.Errorf("component selection is not registered for candidate kind %q", use.Kind)
	}
	language, ok := sourceLanguage(use, family)
	if !ok || !family.supports(language) {
		return nil, fmt.Errorf("unsupported %s source language", family.Label)
	}
	if family.Name != "xss" && !family.ObservationOnly && !family.RequiresAPI && use.APIModel != nil {
		return nil, fmt.Errorf("%s selection must not carry an API contract", family.Label)
	}
	var contract *analysis.APIModel
	if family.RequiresAPI {
		if use.APIModel == nil || use.Completeness == nil || len(use.Completeness.Evidence["sink_binding"]) == 0 {
			return nil, fmt.Errorf("%s component selection needs verified API binding", family.Label)
		}
		contract = familyContract(family, use.APIModel.ID)
		if contract == nil || !reflect.DeepEqual(contract, use.APIModel) {
			return nil, fmt.Errorf("unsupported or conflicting verified %s API contract", family.Label)
		}
		if family.Name == "sql" && (language == lang.Python) == JavaScriptSQLLibrary(contract.Library) {
			return nil, fmt.Errorf("%s language and API capability conflict", family.Label)
		}
	}
	entry := ""
	if len(family.Entries) > 0 {
		entry = use.EntryKind
		if use.EntryFacts != nil {
			if entry != "" && entry != use.EntryFacts.Kind {
				return nil, fmt.Errorf("conflicting entry applicability")
			}
			entry = use.EntryFacts.Kind
		}
		if !contains(family.Entries, "entry."+entry) {
			return nil, fmt.Errorf("unsupported %s entry capability %q", family.Label, entry)
		}
		if family.PythonHTTPOnly && language == lang.Python && entry != "http" {
			return nil, fmt.Errorf("unsupported Python %s entry capability", family.Label)
		}
	}
	roots := []string{family.Pack, languageID(family, language)}
	if entry != "" {
		roots = append(roots, "entry."+entry)
	}
	if contract != nil {
		roots = append(roots, "api."+contract.ID)
	}
	if family.ObservationOnly {
		extra, err := outboundRoots(use, language)
		if err != nil {
			return nil, err
		}
		roots = append(roots, extra...)
		if use.APIModel != nil {
			contract = use.APIModel
		}
	}
	if family.Name == "xss" {
		extra, err := xssRoots(use)
		if err != nil {
			return nil, err
		}
		roots = append(roots, extra...)
	}
	if use.InputFacts != nil {
		if language == lang.Python || use.InputFacts.Validate(use.Dependencies) != nil || (use.EntryFacts != nil && (use.EntryFacts.Kind != use.InputFacts.Acquisition || use.EntryFacts.Location.Span != use.InputFacts.Binding.Span || use.EntryFacts.Location.SHA256 != use.InputFacts.Binding.SHA256)) {
			return nil, fmt.Errorf("invalid Node input facts")
		}
		input := "source.node-input-v1"
		if family.Name == "path" {
			input = "source.node-input-path-v1"
		}
		roots = append(roots, input)
	}
	ids, err := c.closure(roots)
	if err != nil {
		return nil, err
	}
	s := &analysis.ComponentSelection{Pack: c.refs[family.Pack], Components: []analysis.ComponentRef{}, Required: []string{}, Limits: []string{}}
	roles := map[string]bool{}
	if use.Completeness != nil {
		for _, role := range use.Completeness.Required {
			roles[role] = true
		}
	}
	limits := map[string]bool{}
	for _, id := range ids {
		v := c.components[id]
		expected := use.Kind
		switch v.Kind {
		case "language_guidance":
			expected = string(language)
		case "compiled_capability":
			if strings.HasPrefix(v.ID, "entry.") {
				expected = entry
			}
		case "api_contract":
			expected = contract.Library
		}
		applicable := false
		for _, a := range v.Applicability {
			if a == expected {
				applicable = true
			}
		}
		if !applicable {
			return nil, fmt.Errorf("component applicability conflict: %s", id)
		}
		s.Components = append(s.Components, c.refs[id])
		for _, role := range v.Required {
			roles[role] = true
		}
		for _, limit := range v.Limits {
			limits[limit] = true
		}
	}
	for role := range roles {
		s.Required = append(s.Required, role)
	}
	sort.Strings(s.Required)
	for limit := range limits {
		s.Limits = append(s.Limits, limit)
	}
	sort.Strings(s.Limits)
	s.Digest = digest(s)
	return s, nil
}

func contains(items []string, want string) bool {
	for _, v := range items {
		if v == want {
			return true
		}
	}
	return false
}

// Attach records offline selection or explicit coverage failure without altering
// the original source facts, claim blockers, or discovery identities.
func Attach(use *analysis.CandidateUse) {
	if FamFamily(use.Kind) == nil {
		return
	}
	selection, err := Select(*use)
	if err != nil {
		use.Components = &analysis.ComponentSelection{Failure: err.Error()}
		return
	}
	use.Components = selection
}
