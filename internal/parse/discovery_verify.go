package parse

import (
	"crypto/sha256"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"os"
	"path/filepath"
	"strings"
)

// DiscoveryVerifier caches canonical scanner-generated proposals and source
// snapshots. It never reparses modules or accepts model-generated source text.
type DiscoveryVerifier struct {
	root      string
	report    *analysis.AnalysisReport
	canonical map[string]analysis.DiscoveryProposal
	manifest  map[string]string
	hashes    map[string]string
	sources   map[string][]byte
}

func NewDiscoveryVerifier(root string, r *analysis.AnalysisReport) (*DiscoveryVerifier, error) {
	real, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return nil, err
	}
	v := &DiscoveryVerifier{root: real, report: r, canonical: map[string]analysis.DiscoveryProposal{}, manifest: map[string]string{}, sources: map[string][]byte{}, hashes: map[string]string{}}
	for _, p := range r.Discovery {
		v.canonical[p.ID] = p
	}
	for _, e := range r.Files {
		v.manifest[e.Span.File] = e.SHA256
	}
	return v, nil
}

// Refresh intentionally rechecks source after a model call, when concurrent
// edits may have changed a file. Parsing is still performed only once.
func (v *DiscoveryVerifier) Refresh() {
	v.sources = map[string][]byte{}
	v.hashes = map[string]string{}
}
func (v *DiscoveryVerifier) Verify(p analysis.DiscoveryProposal) analysis.DiscoveryProposal {
	p.State = "provisional"
	p.VerifiedEntryID = ""
	reject := func(reason string) analysis.DiscoveryProposal { p.State = "rejected"; p.Reason = reason; return p }
	canonical, ok := v.canonical[p.ID]
	if !ok {
		return reject("proposal is absent from the scanner's canonical inventory")
	}
	refs := append([]analysis.Evidence{p.Registration, p.Handler}, p.Middleware...)
	refs = append(refs, p.Context...)
	want := append([]analysis.Evidence{canonical.Registration, canonical.Handler}, canonical.Middleware...)
	want = append(want, canonical.Context...)
	if len(refs) != len(want) {
		return reject("proposal altered the supplied source alternatives")
	}
	for i, e := range refs {
		expected := want[i]
		if e.Kind != expected.Kind || e.Span != expected.Span || e.SHA256 != expected.SHA256 || e.Text != expected.Text {
			return reject("proposal altered its canonical source reference")
		}
		path := filepath.Clean(e.Span.File)
		resolved, err := filepath.EvalSymlinks(filepath.Join(v.root, path))
		if err == nil {
			resolved, _ = filepath.Abs(resolved)
		}
		if v.manifest[e.Span.File] != e.SHA256 || filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../") || strings.Contains(path, "\\") || err != nil || !strings.HasPrefix(resolved, v.root+string(filepath.Separator)) {
			return reject("proposal source is outside the selected manifest")
		}
		data, exists := v.sources[path]
		if !exists {
			data, err = os.ReadFile(resolved)
			if err != nil {
				return reject("proposal source is unavailable")
			}
			v.sources[path] = data
			v.hashes[path] = fmt.Sprintf("%x", sha256.Sum256(data))
		}
		if v.hashes[path] != e.SHA256 || e.Span.StartByte < 0 || e.Span.EndByte > len(data) || e.Span.EndByte <= e.Span.StartByte || string(data[e.Span.StartByte:e.Span.EndByte]) != e.Text {
			return reject("proposal source hash/span no longer matches")
		}
	}
	// Ignore any supplied model projection and recover the canonical masked text.
	p.Registration = canonical.Registration
	p.Handler = canonical.Handler
	p.Middleware = append([]analysis.Evidence{}, canonical.Middleware...)
	p.Context = append([]analysis.Evidence{}, canonical.Context...)
	if p.ModelChoice == "not_route" {
		return reject("Model did not identify an HTTP registration in this alternative.")
	}
	for _, e := range v.report.Entries {
		if e.Kind != "http" || e.Location.Span != p.Registration.Span || e.Location.SHA256 != p.Registration.SHA256 {
			continue
		}
		for _, d := range v.report.DispatchBindings {
			if d.EntryID != e.ID || d.Resolution != "resolved" || len(d.Gaps) > 0 {
				continue
			}
			for _, c := range v.report.Callables {
				if c.ID == d.CallableID && c.Definition.Span == p.Handler.Span && c.Definition.SHA256 == p.Handler.SHA256 {
					p.VerifiedEntryID = e.ID
					p.State = "verified_existing"
					p.Reason = "Source and callable match an independently established entry; proposed middleware does not create trusted flow."
					return p
				}
			}
		}
	}
	p.Reason = "Source alternatives match, but route/wrapper dispatch is not independently established; proposal remains provisional."
	return p
}
func VerifyDiscovery(root string, p analysis.DiscoveryProposal, r *analysis.AnalysisReport) analysis.DiscoveryProposal {
	v, err := NewDiscoveryVerifier(root, r)
	if err != nil {
		p.State = "rejected"
		p.Reason = err.Error()
		return p
	}
	return v.Verify(p)
}
