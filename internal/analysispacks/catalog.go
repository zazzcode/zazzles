// Package analysispacks selects embedded scanner knowledge without executing analysis adapters.
package analysispacks

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// MaxComponents bounds dependency closure before material or requests are built.
const MaxComponents = 32

// MaxMaterialBytes bounds selected interpretation material, independently of source evidence.
const MaxMaterialBytes = 16 << 10

// Requirement pins one dependency to a supported descriptor version.
type Requirement struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Component describes scanner-owned knowledge and the compiled capability it references.
// Coverage references are catalog metadata and are never sent to the judge.
type Component struct {
	ID            string        `json:"id"`
	Version       string        `json:"version"`
	Kind          string        `json:"kind"`
	Domains       []string      `json:"domains"`
	Applicability []string      `json:"applicability"`
	Compatibility []string      `json:"compatibility"`
	Dependencies  []Requirement `json:"dependencies,omitempty"`
	Owner         string        `json:"owner"`
	CompiledOwner string        `json:"compiled_owner,omitempty"`
	Required      []string      `json:"required,omitempty"`
	Limits        []string      `json:"limits"`
	Tests         []string      `json:"tests"`
	Material      string        `json:"material,omitempty"`
}

type catalog struct {
	components map[string]Component
	refs       map[string]analysis.ComponentRef
}

var embedded, embeddedErr = buildEmbedded()

func buildEmbedded() (*catalog, error) {
	items, err := descriptors()
	if err != nil {
		return nil, err
	}
	return newCatalog(items)
}

// Validate reports invalid embedded configuration before scanning or making model calls.
func Validate() error { return embeddedErr }

func digest(v any) string { b, _ := json.Marshal(v); return fmt.Sprintf("%x", sha256.Sum256(b)) }

// familyRef is a component's reference as one family selects it: the digest
// covers the descriptor with Compatibility narrowed to that family's protocol,
// so another family's protocol bump on a shared component (an input or flow
// capability) does not change this family's selection or request (D-9).
func (c *catalog) familyRef(id, protocol string) analysis.ComponentRef {
	v := c.components[id]
	scoped := v
	scoped.Compatibility = nil
	for _, p := range v.Compatibility {
		if p == protocol {
			scoped.Compatibility = []string{p}
		}
	}
	if scoped.Compatibility == nil {
		return c.refs[id]
	}
	return analysis.ComponentRef{ID: v.ID, Version: v.Version, Digest: digest(scoped)}
}

func newCatalog(items []Component) (*catalog, error) {
	protocols := map[string]bool{}
	for _, f := range Families() {
		protocols[familyProtocol(f.Name)] = true
	}
	return newCatalogKnown(items, protocols)
}

// newCatalogKnown builds a catalog that accepts the given family protocols.
func newCatalogKnown(items []Component, protocols map[string]bool) (*catalog, error) {
	c := &catalog{map[string]Component{}, map[string]analysis.ComponentRef{}}
	for _, v := range items {
		if v.ID == "" || v.Version == "" || v.Kind == "" || v.Owner == "" || len(v.Domains) == 0 || len(v.Applicability) == 0 || len(v.Tests) == 0 || len(v.Compatibility) == 0 {
			return nil, fmt.Errorf("invalid component descriptor %q", v.ID)
		}
		for _, protocol := range v.Compatibility {
			if !protocols[protocol] {
				return nil, fmt.Errorf("component %s declares unknown family protocol %q", v.ID, protocol)
			}
		}
		if _, ok := c.components[v.ID]; ok {
			return nil, fmt.Errorf("duplicate component %s", v.ID)
		}
		c.components[v.ID] = v
		c.refs[v.ID] = analysis.ComponentRef{ID: v.ID, Version: v.Version, Digest: digest(v)}
	}

	// Each family's registered roots and claim protocol are part of embedded
	// configuration. A missing root or drifted question set is a broken
	// scanner configuration, not unsupported target coverage.
	for _, f := range Families() {
		for _, id := range f.rootIDs() {
			if _, ok := c.components[id]; !ok {
				return nil, fmt.Errorf("required embedded component missing: %s", id)
			}
		}
		if f.ObservationOnly {
			if err := c.validateObservation(&f); err != nil {
				return nil, err
			}
		}
		if !f.ObservationOnly {
			if _, _, err := c.claimQuestions(&f); err != nil {
				return nil, err
			}
		}
		for _, language := range f.Languages {
			component := c.components[languageID(&f, language)]
			if !contains(component.Applicability, string(language)) {
				return nil, fmt.Errorf("component %s does not support registered %s language %s", component.ID, f.Name, language)
			}
		}
	}
	for id := range c.components {
		if _, err := c.closure([]string{id}); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *catalog) closure(roots []string) ([]string, error) {
	state := map[string]int{}
	var visit func(string) error
	visit = func(id string) error {
		v, ok := c.components[id]
		if !ok {
			return fmt.Errorf("required component missing: %s", id)
		}
		if state[id] == 1 {
			return fmt.Errorf("component dependency cycle: %s", id)
		}
		if state[id] == 2 {
			return nil
		}
		state[id] = 1
		for _, r := range v.Dependencies {
			d, ok := c.components[r.ID]
			if !ok || d.Version != r.Version {
				return fmt.Errorf("incompatible dependency %s for %s", r.ID, id)
			}
			if err := visit(r.ID); err != nil {
				return err
			}
		}
		state[id] = 2
		return nil
	}
	for _, id := range roots {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	if len(state) > MaxComponents {
		return nil, fmt.Errorf("component count exceeds %d", MaxComponents)
	}
	singletons := map[string]string{}
	for id := range state {
		kind := c.components[id].Kind
		if kind == "language_guidance" || kind == "api_contract" || kind == "claim_questions" || kind == "rendering_contract" {
			if old := singletons[kind]; old != "" && old != id {
				return nil, fmt.Errorf("conflicting required %s components", kind)
			}
			singletons[kind] = id
		}
	}
	ids := make([]string, 0, len(state))
	for id := range state {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}
