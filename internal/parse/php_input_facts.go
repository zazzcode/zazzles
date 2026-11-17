package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// phpInputSource records acquisition origin per invocation.
type phpInputSource struct {
	origin    string
	container string
}

// superscriptOrigin maps a superglobal access to its acquisition origin.
func superscriptOrigin(name string) (container, origin string, ok bool) {
	switch name {
	case "_GET":
		return "GET", "http.query", true
	case "_POST":
		return "POST", "http.form", true
	case "_REQUEST":
		return "REQUEST", "http.query_or_form", true
	case "_COOKIE":
		return "COOKIE", "http.cookies", true
	case "_FILES":
		return "FILES", "http.upload", true
	case "_SERVER":
		return "SERVER", "http.headers", true
	case "_SESSION":
		return "_SESSION", "session", true
	}
	return "", "", false
}

// phpUnwritten marks a session read with no writer linked yet at read time.
// Non-XSS families treat it as unknown; the XSS render path treats the content
// as unescaped and lets linkStorage resolve the origin against every entry's
// writes once all entries were analyzed.
const phpUnwritten = "unwritten"

// phpRequestContainer reports a superglobal whose whole value is request
// controlled ($_SERVER mixes server facts and headers; $_SESSION is storage).
func phpRequestContainer(container string) bool {
	switch container {
	case "GET", "POST", "REQUEST", "COOKIE", "FILES":
		return true
	}
	return false
}

// serverKeyOrigin maps selected $_SERVER keys to precise origins.
func serverKeyOrigin(key string) string {
	switch {
	case strings.HasPrefix(key, "HTTP_"):
		return "http.headers"
	case key == "REQUEST_URI", key == "PATH_INFO", key == "PHP_SELF":
		return "http.url_path"
	case key == "QUERY_STRING":
		return "http.query"
	}
	return "unknown"
}

// source records an acquisition fact at a superglobal access.
func (f *phpFlow) source(n *sitter.Node, container, origin, key string) phpValue {
	kind := "input_source"
	if container == "_SESSION" {
		// A session container is storage, not an untrusted request origin:
		// prior writes link as transfers.
		kind = "storage_source"
	}
	e := f.module.evidence(kind, n)
	dep := analysis.Dependency{Source: e, Transfers: []analysis.Evidence{}}
	v := phpValue{deps: []phpDep{{dep: dep, protection: "raw", container: container, key: key}}}
	if container == "_SESSION" {
		key0 := "php-session:" + key
		v.deps[0].dep.StorageKey = key0
		for _, w := range f.set.sessionWrites[key0] {
			for _, wd := range w.value.deps {
				nd := wd
				nd.dep.StorageKey = key0
				nd.dep.Transfers = append(append([]analysis.Evidence{}, nd.dep.Transfers...), w.evidence)
				nd.entry = w.entry
				v.deps = append(v.deps, nd)
			}
		}
		if len(f.set.sessionWrites[key0]) == 0 {
			v.deps[0].protection = phpUnwritten
		}
	}
	f.recordInput(e, container, key, origin)
	return v
}

// recordInput indexes acquisition per invocation context.
func (f *phpFlow) recordInput(source analysis.Evidence, container, key, origin string) {
	if f.set.inputs == nil {
		f.set.inputs = map[string]map[analysis.Evidence]phpInputSource{}
	}
	inputs := f.set.inputs[f.invocation.ID]
	if inputs == nil {
		inputs = map[analysis.Evidence]phpInputSource{}
		f.set.inputs[f.invocation.ID] = inputs
	}
	inputs[source] = phpInputSource{origin: origin, container: container}
}

// assemblePHPInputs builds InputFacts after storage linking finalized the
// dependencies. Facts mirror final paths; initial acquisition never certifies
// the current operand.
func (s *phpSet) assemblePHPInputs(out *analysis.AnalysisReport) {
	entries := map[string]analysis.EntryPoint{}
	for _, entry := range out.Entries {
		entries[entry.ID] = entry
	}
	for i := range out.Uses {
		u := &out.Uses[i]
		e := entries[u.EntryID]
		if e.HTTP == nil {
			continue
		}
		facts := &analysis.InputFacts{
			Version: 1, Acquisition: "http", Framework: e.HTTP.Framework, Binding: e.Location,
			Values: []analysis.InputValueFact{}, Controls: append([]analysis.Evidence{}, u.Context...),
			Gaps: phpMergeGaps(e.Gaps, u.Gaps),
		}
		if u.Completeness != nil {
			facts.Gaps = phpMergeGaps(facts.Gaps, u.Completeness.Blockers)
		}
		for j, dep := range u.Dependencies {
			origin := "unknown"
			if source, ok := s.inputs[u.InvocationContextID][dep.Source]; ok {
				origin = source.origin
			}
			if origin == "http.upload" {
				origin = phpUploadOrigin(dep)
			}
			switch dep.Source.Kind {
			case "storage_source":
				origin = "storage"
			}
			facts.Values = append(facts.Values, analysis.InputValueFact{
				Dependency: j, Origin: origin, InitialType: "unknown", SinkType: "unknown",
				Source: dep.Source, Transfers: append([]analysis.Evidence{}, dep.Transfers...),
			})
		}
		u.InputFacts = facts
	}
}

// phpUploadOrigin refines $_FILES field projections: the client-supplied name
// and the server-managed tmp_name carry different facts.
func phpUploadOrigin(dep analysis.Dependency) string {
	for _, transfer := range dep.Transfers {
		if transfer.Kind != "field_projection" {
			continue
		}
		switch transfer.Text {
		case "name", "full_path":
			return "http.upload_filename"
		case "tmp_name":
			return "http.upload_content"
		}
	}
	return "http.upload"
}
