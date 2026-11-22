package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// phpInputSource records acquisition origin per invocation.
type phpInputSource struct {
	origin    string
	container string
	key       string
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
	case key == "SERVER_NAME":
		// Follows the Host header unless the server pins a canonical name.
		return "http.headers"
	}
	return "unknown"
}

// phpServerDetermined reports $_SERVER keys whose value the server chooses
// (script location, addresses, ports, timestamps): not request content.
// Unlisted keys stay conservative request sources; REQUEST_METHOD stays one
// because HTTP method tokens may contain quotes.
func phpServerDetermined(key string) bool {
	switch key {
	case "SCRIPT_NAME", "SCRIPT_FILENAME", "DOCUMENT_ROOT", "CONTEXT_DOCUMENT_ROOT", "SERVER_ADDR", "SERVER_PORT", "SERVER_SOFTWARE", "SERVER_PROTOCOL", "GATEWAY_INTERFACE", "REMOTE_ADDR", "REMOTE_PORT", "REQUEST_TIME", "REQUEST_TIME_FLOAT":
		return true
	}
	return false
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
		writes := f.set.scopedStorageWrites(key0, f.entry.ID, f.set.storageProjectIndex(f.report))
		for _, w := range writes {
			for _, wd := range w.value.deps {
				nd := wd
				nd.dep.StorageKey = key0
				nd.dep.Transfers = append(append([]analysis.Evidence{}, nd.dep.Transfers...), w.evidence)
				nd.entry = w.entry
				v.deps = append(v.deps, nd)
			}
		}
		if len(writes) == 0 {
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
	inputs[source] = phpInputSource{origin: origin, container: container, key: key}
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
				if facts.Framework == "symfony" && source.key != "" && dep.Source.Kind == "input_source" {
					facts.Stages = append(facts.Stages, analysis.InputStage{Name: "request_field", Order: j, Scope: source.key, Evidence: dep.Source})
				}
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
		if facts.Framework == "symfony" {
			for _, dep := range u.Dependencies {
				for _, transfer := range dep.Transfers {
					if transfer.Kind == "typed_conversion" {
						facts.Controls = append(facts.Controls, transfer)
					}
				}
			}
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

// phpStoredOnlyBlockers blocks an injection claim whose only content-bearing
// paths are stored reads (php-sql: rows, php-session: values) with no
// request-linked writer in the supplied evidence: a lookup key alone does not
// establish who wrote a stored value. Request paths reduced to numeric or
// non-content values (md5, intval) carry no syntax. Session reads whose
// request writes were linked carry request sources and are not stored-only.
func phpStoredOnlyBlockers(deps []phpDep, at analysis.Span) []analysis.Gap {
	stored := false
	for _, d := range deps {
		if d.protection == "numeric" || d.protection == "non_content" {
			continue
		}
		switch d.dep.Source.Kind {
		case "input_source":
			return nil
		case "storage_source":
			stored = true
		}
	}
	if !stored {
		return nil
	}
	return []analysis.Gap{{Kind: "storage_origin_unresolved", Detail: "Only stored values reach this operation as content; no request-linked writer is established for them.", At: at}}
}

// phpStoredKeys lists the storage keys of a value's content-bearing stored paths.
func phpStoredKeys(deps []phpDep) []string {
	var keys []string
	for _, d := range deps {
		if d.dep.Source.Kind == "storage_source" && d.protection != "numeric" && d.protection != "non_content" {
			keys = parse.AppendUniqueString(keys, d.dep.StorageKey)
		}
	}
	return keys
}

// linkStoredOnlySessions resolves stored-only SQL claims once every entry was
// analyzed: a session key written from a request value in any entry links
// those request sources into the claim and lifts its stored-only blocker. A
// key with no request-derived writer keeps the claim in Review.
func (s *phpSet) linkStoredOnlySessions(out *analysis.AnalysisReport) {
	projects := s.storageProjectIndex(out)
	for i := range out.Uses {
		u := &out.Uses[i]
		keys, ok := s.storedOnly[u.ID]
		if !ok || u.Completeness == nil {
			continue
		}
		seen := map[analysis.Span]bool{}
		for _, d := range u.Dependencies {
			seen[d.Source.Span] = true
		}
		linked := false
		for _, key := range keys {
			if !strings.HasPrefix(key, "php-session:") {
				continue
			}
			for _, w := range s.scopedStorageWrites(key, u.EntryID, projects) {
				for _, wd := range w.value.deps {
					if wd.dep.Source.Kind != "input_source" || wd.protection == "numeric" || wd.protection == "non_content" || seen[wd.dep.Source.Span] {
						continue
					}
					seen[wd.dep.Source.Span] = true
					nd := wd.dep
					nd.StorageKey = key
					nd.SinkSlot = "sql_text"
					nd.Transfers = append(append([]analysis.Evidence{}, nd.Transfers...), w.evidence)
					u.Dependencies = append(u.Dependencies, nd)
					u.Completeness.Evidence["input_source"] = append(u.Completeness.Evidence["input_source"], nd.Source)
					linked = true
				}
			}
		}
		if !linked {
			continue
		}
		blockers := u.Completeness.Blockers[:0]
		for _, g := range u.Completeness.Blockers {
			if g.Kind != "storage_origin_unresolved" {
				blockers = append(blockers, g)
			}
		}
		u.Completeness.Blockers = blockers
	}
}
