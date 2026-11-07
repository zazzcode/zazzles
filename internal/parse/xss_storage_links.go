package parse

import (
	"fmt"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// compactStoredPaths keeps one path per source, write and protection class once a
// sink has more paths than a judgment can carry. Each source, write and unsafe class
// stays; only repeats that differ in later reads of the same value are dropped, and
// the record states how many.
func compactStoredPaths(u *analysis.CandidateUse, deps []analysis.Dependency, protections, entries []string) ([]analysis.Dependency, []string, []string) {
	if len(deps) <= 8 {
		return deps, protections, entries
	}
	seen := map[string]bool{}
	var keptDeps []analysis.Dependency
	var keptProtections, keptEntries []string
	for i, d := range deps {
		write := ""
		for _, e := range d.Transfers {
			if e.Kind == "storage_write" {
				write = fmt.Sprintf("%s:%d", e.Span.File, e.Span.StartByte)
			}
		}
		key := fmt.Sprintf("%s:%d|%s|%s|%s", d.Source.Span.File, d.Source.Span.StartByte, d.StorageKey, write, protections[i])
		if seen[key] {
			continue
		}
		seen[key] = true
		keptDeps = append(keptDeps, d)
		keptProtections = append(keptProtections, protections[i])
		keptEntries = append(keptEntries, entries[i])
	}
	if dropped := len(deps) - len(keptDeps); dropped > 0 {
		u.Gaps = append(u.Gaps, analysis.Gap{Kind: "stored_paths_compacted", Detail: fmt.Sprintf("%d stored paths repeating a source, write and protection class are omitted", dropped), At: u.Sink.Span})
	}
	return keptDeps, keptProtections, keptEntries
}

// generatedIdentifier reports a read of a Mongoose _id with no request write. The
// database generates it, so it cannot carry markup. A written _id stays a normal field.
func (s *moduleSet) generatedIdentifier(u analysis.CandidateUse) bool {
	for _, d := range u.Dependencies {
		if !strings.HasPrefix(d.StorageKey, "mongoose:") || !strings.HasSuffix(d.StorageKey, "._id") || len(s.storageWrites[d.StorageKey]) > 0 {
			return false
		}
	}
	return len(u.Dependencies) > 0
}

func (s *moduleSet) linkStoredXSS(report *analysis.AnalysisReport) {
	kept := report.Uses[:0]
	for _, u := range report.Uses {
		if u.XSS == nil || u.XSS.Type != "stored" || !s.generatedIdentifier(u) {
			kept = append(kept, u)
		}
	}
	report.Uses = kept
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.XSS == nil || u.XSS.Type != "stored" {
			continue
		}
		var dependencies []analysis.Dependency
		var entries []string
		related := map[string]bool{}
		resolved := true
		for _, read := range u.Dependencies {
			if read.StorageKey == "" {
				dependencies = append(dependencies, read)
				entries = append(entries, "")
				continue
			}
			writes := append([]storageWrite{}, s.storageWrites[read.StorageKey]...)
			sort.SliceStable(writes, func(i, j int) bool {
				a, b := writes[i].sink.Span, writes[j].sink.Span
				if a.File != b.File {
					return a.File < b.File
				}
				return a.StartByte < b.StartByte
			})
			if len(writes) == 0 {
				resolved = false
				dependencies = append(dependencies, read)
				entries = append(entries, "")
				continue
			}
			u.XSS.StorageKey = read.StorageKey
			for _, write := range writes {
				related[write.route] = true
				for _, origin := range write.value.deps {
					if len(dependencies) >= 64 {
						resolved = false
						continue
					}
					origin.Transfers = append(append([]analysis.Evidence{}, origin.Transfers...), write.sink, read.Source)
					origin.Transfers = append(origin.Transfers, read.Transfers...)
					dependencies = append(dependencies, origin)
					entries = append(entries, write.route)
				}
			}
		}
		u.Dependencies = dependencies
		u.XSS.OriginResolved = resolved
		linked := resolved
		for id := range related {
			u.XSS.RelatedEntries = append(u.XSS.RelatedEntries, id)
		}
		sort.Strings(u.XSS.RelatedEntries)
		f := flow{set: s}
		if u.XSS.Protection != "encoded" {
			var protections []string
			u.XSS.Protection, u.XSS.ProtectionReason, protections = f.xssPathProtection(value{deps: dependencies}, u.XSS.OutputContext, false)
			dependencies, protections, entries = compactStoredPaths(u, dependencies, protections, entries)
			u.Dependencies = dependencies
			u.XSS.Paths = xssPaths(protections, entries)
			// A read with no write stays visible, but cannot hide a complete unsafe path.
			for j, p := range protections {
				if dependencies[j].StorageKey == "" && (p == "raw" || p == "ineffective") {
					linked = true
				}
			}
		}
		if linked && !resolved {
			u.XSS.OriginResolved = true
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "storage_origin_partial", Detail: "A sibling storage read has no established write; a complete unsafe path is reported beside it.", At: u.Sink.Span})
		}
	}
}
