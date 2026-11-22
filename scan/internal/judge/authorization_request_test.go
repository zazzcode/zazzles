package judge

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

// Entry access and state changes are context. They do not change the request
// bytes of a use this family does not own.
func TestExistingFamilyRequestsUnchanged(t *testing.T) {
	r, err := pipeline.Analyze(filepath.Join("..", "langphp", "testdata", "symfony", "doctrine-storage"), "")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, u := range r.Uses {
		if u.Kind == analysis.AuthorizationKind || u.EntryFacts == nil {
			continue
		}
		seen++
		full, err := json.Marshal(wireBundle(u))
		if err != nil {
			t.Fatal(err)
		}
		facts := *u.EntryFacts
		facts.Access, facts.StateChanges = nil, nil
		cleared := u
		cleared.EntryFacts = &facts
		bare, err := json.Marshal(wireBundle(cleared))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(full, bare) {
			t.Fatalf("%s request changed when access was removed", u.Kind)
		}
	}
	if seen == 0 {
		t.Fatal("fixture has no pre-existing use")
	}
}

// The SSRF request is the SSRF use. Linking its id onto an authorization
// candidate does not add authorization facts to that use.
func TestSSRFWireOmitsAuthorization(t *testing.T) {
	r, err := pipeline.Analyze(filepath.Join("..", "langphp", "testdata", "symfony", "authorization"), "")
	if err != nil {
		t.Fatal(err)
	}
	var ssrf analysis.CandidateUse
	linked := false
	for _, u := range r.Uses {
		if u.Kind == "ssrf_candidate" {
			ssrf = u
		}
		if u.Authorization != nil && len(u.Authorization.ServerSideRequests) > 0 {
			linked = true
		}
	}
	if ssrf.ID == "" || !linked {
		t.Fatal("fixture did not link an address-guarded candidate to an ssrf use")
	}
	raw, err := json.Marshal(wireBundle(ssrf))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(`"authorization"`)) {
		t.Fatal("ssrf request contains authorization")
	}
}
