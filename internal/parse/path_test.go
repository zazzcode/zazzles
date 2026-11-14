package parse

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func pathUses(r *analysis.AnalysisReport) map[string]analysis.CandidateUse {
	routes := map[string]string{}
	for _, e := range r.Entries {
		routes[e.ID] = e.HTTPRoute().PathPattern
	}
	out := map[string]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "path_traversal_candidate" {
			out[routes[u.EntryID]] = u
		}
	}
	return out
}

type pathCase struct {
	operation  string
	role       string
	protection string // protection of the single request path flow
	guards     []string
	transforms []string
	decoded    bool
	blocked    bool // a blocker touches the flow
	root       string
	file       string // sink file suffix
}

func guardKinds(u analysis.CandidateUse) []string {
	var kinds []string
	for _, g := range u.Path.Guards {
		kinds = append(kinds, g.Kind)
	}
	return kinds
}

func checkPathCase(t *testing.T, route string, u analysis.CandidateUse, want pathCase) {
	t.Helper()
	f := u.Path
	if f == nil {
		t.Fatalf("%s: no path facts", route)
	}
	if err := f.Validate(len(u.Dependencies), len(u.Context)); err != nil {
		t.Fatalf("%s: invalid path facts: %v", route, err)
	}
	if f.Operation != want.operation || f.Role != want.role || f.Platform != "posix" {
		t.Fatalf("%s: operation=%s role=%s platform=%s", route, f.Operation, f.Role, f.Platform)
	}
	if u.APIModel == nil || u.APIModel.ID != f.ContractID || analysispacks.PathContract(f.ContractID) == nil {
		t.Fatalf("%s: contract %+v", route, u.APIModel)
	}
	if len(f.Paths) == 0 {
		t.Fatalf("%s: no path flows", route)
	}
	for _, p := range f.Paths {
		if p.Operand != analysis.PathSlotFile || u.Dependencies[p.Dependency].SinkSlot != analysis.PathSlotFile {
			t.Fatalf("%s: a non-path operand became a path flow: %+v", route, p)
		}
	}
	p := f.Paths[0]
	if p.Protection != want.protection {
		t.Fatalf("%s: protection %s (%s), want %s; blockers %+v", route, p.Protection, p.Reason, want.protection, u.Completeness.Blockers)
	}
	if got := guardKinds(u); strings.Join(got, ",") != strings.Join(want.guards, ",") {
		t.Fatalf("%s: guard kinds %v, want %v", route, got, want.guards)
	}
	for _, tr := range want.transforms {
		found := false
		for _, have := range p.Transforms {
			found = found || have == tr
		}
		if !found {
			t.Fatalf("%s: transform %s missing in %v", route, tr, p.Transforms)
		}
	}
	if p.DecodedAfterGuard != want.decoded {
		t.Fatalf("%s: decoded_after_guard=%v", route, p.DecodedAfterGuard)
	}
	if want.root != "" && p.Root != want.root {
		t.Fatalf("%s: root %q, want %q", route, p.Root, want.root)
	}
	if want.file != "" && !strings.HasSuffix(u.Sink.Span.File, want.file) {
		t.Fatalf("%s: sink file %s", route, u.Sink.Span.File)
	}
	if u.Completeness == nil || u.Completeness.ClaimKind != "path_traversal" {
		t.Fatalf("%s: completeness %+v", route, u.Completeness)
	}
	for _, role := range pathRequiredRoles {
		if len(u.Completeness.Evidence[role]) == 0 {
			t.Fatalf("%s: role %s has no evidence", route, role)
		}
	}
	if want.blocked != (p.Protection == "unknown") {
		t.Fatalf("%s: blocked=%v protection=%s", route, want.blocked, p.Protection)
	}
	if !want.blocked && len(u.Completeness.Blockers) != 0 {
		t.Fatalf("%s: unexpected blockers: %+v", route, u.Completeness.Blockers)
	}
	if u.Components == nil || u.Components.Failure != "" || len(u.Components.Components) == 0 {
		t.Fatalf("%s: component selection %+v", route, u.Components)
	}
	for _, d := range u.Dependencies {
		if d.Source.SHA256 == "" || d.Source.Span.File == "" {
			t.Fatalf("%s: dependency lacks snapshot reference: %+v", route, d.Source)
		}
	}
}

func TestPathJSOperands(t *testing.T) {
	r := analyzeFixture(t, "typescript/path-traversal")
	uses := pathUses(r)
	read, resolve := "fs.readFile", "fs.readFileSync"
	for route, want := range map[string]pathCase{
		"/v/join-read":          {operation: read, role: "read", protection: "raw", transforms: []string{"join"}, root: "__dirname"},
		"/v/resolve-sync":       {operation: resolve, role: "read", protection: "raw", transforms: []string{"resolve"}, root: "ROOT"},
		"/v/write":              {operation: "fs.writeFile", role: "write", protection: "raw", transforms: []string{"join"}},
		"/v/promises":           {operation: "fs/promises.readFile", role: "read", protection: "raw", transforms: []string{"join"}},
		"/v/normalize-only":     {operation: resolve, role: "read", protection: "raw", transforms: []string{"normalize"}},
		"/v/direct":             {operation: read, role: "read", protection: "raw"},
		"/v/try-catch":          {operation: resolve, role: "read", protection: "raw"},
		"/v/blacklist":          {operation: resolve, role: "read", protection: "guarded", guards: []string{"dotdot_text"}, transforms: []string{"decode"}, decoded: true},
		"/v/reassigned":         {operation: resolve, role: "read", protection: "raw"},
		"/v/sibling-branch":     {operation: resolve, role: "read", protection: "raw"},
		"/v/helper":             {operation: resolve, role: "read", protection: "raw", transforms: []string{"join"}},
		"/p/allowlist":          {operation: resolve, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/allowlist-array":    {operation: resolve, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/prefix-boundary":    {operation: resolve, role: "read", protection: "guarded", guards: []string{"prefix_boundary"}, transforms: []string{"resolve"}},
		"/p/relative":           {operation: resolve, role: "read", protection: "guarded", guards: []string{"relative"}},
		"/p/realpath":           {operation: resolve, role: "read", protection: "guarded", guards: []string{"relative"}, transforms: []string{"realpath"}},
		"/u/prefix-bare":        {operation: resolve, role: "read", protection: "guarded", guards: []string{"prefix_bare"}},
		"/u/missing-helper":     {operation: resolve, role: "read", protection: "unknown", blocked: true},
		"/u/basename":           {operation: resolve, role: "read", protection: "raw", transforms: []string{"reduce"}},
		"/p/helper-guard":       {operation: resolve, role: "read", protection: "guarded", guards: []string{"allowlist"}, transforms: []string{"join"}},
		"/u/helper-two-callers": {operation: resolve, role: "read", protection: "unknown", blocked: true, guards: []string{"allowlist"}},
		"/v/url":                {operation: resolve, role: "read", protection: "raw", transforms: []string{"join"}},
		"/static":               {operation: read, role: "read", protection: "guarded", guards: []string{"prefix_bare"}, transforms: []string{"resolve"}},
	} {
		t.Run(route, func(t *testing.T) {
			u, ok := uses[route]
			if !ok {
				t.Fatalf("no path candidate for %s", route)
			}
			checkPathCase(t, route, u, want)
		})
	}
	for _, route := range []string{"/n/constant", "/n/content-only", "/n/shadowed-param", "/n/fake-object", "/n/send-constant"} {
		if _, ok := uses[route]; ok {
			t.Fatalf("%s must not be a path candidate", route)
		}
	}
	t.Run("write content is not a path source", func(t *testing.T) {
		u := uses["/v/write"]
		var content *analysis.PathOperand
		for i := range u.Path.Operands {
			if u.Path.Operands[i].Slot == analysis.PathSlotContent {
				content = &u.Path.Operands[i]
			}
		}
		if content == nil || len(content.Dependencies) != 1 || u.Dependencies[content.Dependencies[0]].Source.Text != "req.body.data" {
			t.Fatalf("content operand: %+v", content)
		}
		if len(u.Path.Paths) != 1 || u.Dependencies[u.Path.Paths[0].Dependency].Source.Text != "req.body.name" {
			t.Fatalf("path flows: %+v", u.Path.Paths)
		}
	})
	t.Run("witness dependency keeps its source and transfers", func(t *testing.T) {
		u := uses["/v/join-read"]
		dep := u.Dependencies[u.Path.Paths[0].Dependency]
		if dep.Source.Text != "req.query.filename" || dep.SinkSlot != analysis.PathSlotFile || len(dep.Transfers) == 0 {
			t.Fatalf("dependency: %+v", dep)
		}
		if !strings.Contains(u.Sink.Text, "fs.readFile(filePath") {
			t.Fatalf("sink: %s", u.Sink.Text)
		}
	})
}

func TestPathCommonJSBindings(t *testing.T) {
	r := analyzeFixture(t, "javascript/path-traversal")
	uses := pathUses(r)
	for route, want := range map[string]pathCase{
		"/cjs/read":          {operation: "fs.readFile", role: "read", protection: "raw", transforms: []string{"join"}, file: "server.js"},
		"/cjs/destructured":  {operation: "fs.readFileSync", role: "read", protection: "raw", transforms: []string{"join"}},
		"/cjs/aliased-write": {operation: "fs.writeFile", role: "write", protection: "raw", transforms: []string{"join"}},
		"/cjs/promises":      {operation: "fs/promises.readFile", role: "read", protection: "raw", transforms: []string{"join"}},
		"/cjs/guarded":       {operation: "fs.readFileSync", role: "read", protection: "guarded", guards: []string{"prefix_boundary"}},
	} {
		t.Run(route, func(t *testing.T) {
			u, ok := uses[route]
			if !ok {
				t.Fatalf("no path candidate for %s", route)
			}
			checkPathCase(t, route, u, want)
		})
	}
	for _, route := range []string{"/cjs/local-module", "/cjs/reassigned"} {
		if _, ok := uses[route]; ok {
			t.Fatalf("%s must not carry the verified fs contract", route)
		}
	}
}

func TestPathPythonOperands(t *testing.T) {
	r := analyzeFixture(t, "python/path-traversal")
	uses := pathUses(r)
	open := "open"
	for route, want := range map[string]pathCase{
		"/v/open":            {operation: open, role: "read", protection: "raw", file: "app.py"},
		"/v/join":            {operation: open, role: "read", protection: "raw", transforms: []string{"join"}},
		"/v/write":           {operation: open, role: "write", protection: "raw"},
		"/v/io-open":         {operation: "io.open", role: "read", protection: "raw"},
		"/v/pathlib-read":    {operation: "pathlib.Path.read_text", role: "read", protection: "raw", transforms: []string{"join"}},
		"/v/pathlib-bytes":   {operation: "pathlib.Path.read_bytes", role: "read", protection: "raw", transforms: []string{"path_object"}},
		"/v/pathlib-write":   {operation: "pathlib.Path.write_text", role: "write", protection: "raw"},
		"/v/normpath-only":   {operation: open, role: "read", protection: "raw", transforms: []string{"normalize"}},
		"/v/try-except":      {operation: open, role: "read", protection: "raw"},
		"/v/blacklist":       {operation: open, role: "read", protection: "guarded", guards: []string{"dotdot_text"}},
		"/v/reassigned":      {operation: open, role: "read", protection: "raw"},
		"/v/sibling-branch":  {operation: open, role: "read", protection: "raw"},
		"/v/helper":          {operation: open, role: "read", protection: "raw", transforms: []string{"join"}},
		"/p/allowlist":       {operation: open, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/allowlist-tuple": {operation: open, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/prefix-boundary": {operation: open, role: "read", protection: "guarded", guards: []string{"prefix_boundary"}},
		"/p/commonpath":      {operation: open, role: "read", protection: "guarded", guards: []string{"commonpath"}},
		"/p/realpath":        {operation: open, role: "read", protection: "guarded", guards: []string{"commonpath"}, transforms: []string{"realpath"}},
		"/u/prefix-bare":     {operation: open, role: "read", protection: "guarded", guards: []string{"prefix_bare"}},
		"/u/missing-helper":  {operation: open, role: "read", protection: "unknown", blocked: true},
		"/u/basename":        {operation: open, role: "read", protection: "raw", transforms: []string{"reduce"}},
	} {
		t.Run(route, func(t *testing.T) {
			u, ok := uses[route]
			if !ok {
				t.Fatalf("no path candidate for %s", route)
			}
			checkPathCase(t, route, u, want)
		})
	}
	for _, route := range []string{"/n/constant", "/n/content-only", "/n/stored", "/n/shadow-def", "/n/shadow-import", "/n/shadow-local"} {
		if _, ok := uses[route]; ok {
			t.Fatalf("%s must not be a path candidate", route)
		}
	}
	t.Run("write text is not a path source", func(t *testing.T) {
		for _, route := range []string{"/v/write", "/v/pathlib-write"} {
			u := uses[route]
			for _, p := range u.Path.Paths {
				if src := u.Dependencies[p.Dependency].Source.Text; strings.Contains(src, "text") {
					t.Fatalf("%s: write content became a path flow: %s", route, src)
				}
			}
		}
	})
}

func TestPathComprehensionSelectionIsUnknown(t *testing.T) {
	src := analysis.Evidence{Kind: "input_source", Text: `environ["PATH_INFO"]`, Span: analysis.Span{File: "app.py"}}
	for name, tt := range map[string]struct {
		transfer string
		kind     string
		want     string
	}{
		"registry element selected by equality": {`[s for s in TRIGGER_MAP.keys() if s == name][0]`, "field_projection", "unknown"},
		"plain index of a list":                 {`parts[1]`, "field_projection", "raw"},
		"comprehension without an index":        {`[s for s in names]`, "field_projection", "raw"},
	} {
		t.Run(name, func(t *testing.T) {
			dep := analysis.Dependency{SinkSlot: analysis.PathSlotFile, Source: src, Transfers: []analysis.Evidence{{Kind: tt.kind, Text: tt.transfer, Span: analysis.Span{File: "app.py"}}}}
			u := &analysis.CandidateUse{Dependencies: []analysis.Dependency{dep}, Path: &analysis.PathFacts{Operation: "open", Platform: "posix", Role: "read",
				Operands: []analysis.PathOperand{{Slot: analysis.PathSlotFile}}, Paths: []analysis.PathFlow{{Dependency: 0, Operand: analysis.PathSlotFile, Protection: "raw"}}}}
			c := &analysis.Completeness{Evidence: map[string][]analysis.Evidence{}}
			finishPathFlows(u, c, nil, nil, newPathGuardInfo(), func(analysis.Gap, analysis.Dependency) bool { return false })
			if got := u.Path.Paths[0].Protection; got != tt.want {
				t.Fatalf("protection %s, want %s", got, tt.want)
			}
		})
	}
}

// TestPathGraphQLAndGRPCEntries checks that the same path claim attaches to the
// shared GraphQL resolver and unary gRPC handler contexts, with the request field
// as the source and the guard attributed to its own resolver only.
func TestPathGraphQLAndGRPCEntries(t *testing.T) {
	for _, tt := range []struct {
		dir        string
		operations map[string]string // sink function suffix -> expected flow protection ("" = no candidate)
		kind       string
	}{
		{"javascript/path-traversal/graphql", map[string]string{"report": "raw", "listed": "guarded", "fixed": ""}, "graphql"},
		{"javascript/path-traversal/grpc", map[string]string{"fetch": "raw", "fixed": ""}, "grpc"},
	} {
		t.Run(tt.dir, func(t *testing.T) {
			r := analyzeFixture(t, tt.dir)
			byEntry := map[string]analysis.EntryPoint{}
			for _, e := range r.Entries {
				byEntry[e.ID] = e
			}
			got := map[string]analysis.CandidateUse{}
			for _, u := range r.Uses {
				if u.Kind != "path_traversal_candidate" {
					continue
				}
				e := byEntry[u.EntryID]
				if e.Kind != tt.kind {
					t.Fatalf("entry kind %s, want %s", e.Kind, tt.kind)
				}
				name := ""
				if tt.kind == "grpc" {
					name = strings.ToLower(e.GRPC.Method)
				} else {
					name = e.GraphQL.Field
				}
				got[name] = u
			}
			for name, want := range tt.operations {
				u, ok := got[name]
				if want == "" {
					if ok {
						t.Fatalf("%s must not be a candidate", name)
					}
					continue
				}
				if !ok {
					t.Fatalf("no candidate for %s (have %v)", name, len(got))
				}
				if err := u.Path.Validate(len(u.Dependencies), len(u.Context)); err != nil {
					t.Fatal(err)
				}
				if p := u.Path.Paths[0]; p.Protection != want {
					t.Fatalf("%s: protection %s (%s), want %s; blockers %+v", name, p.Protection, p.Reason, want, u.Completeness.Blockers)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("%s: component selection %+v", name, u.Components)
				}
			}
		})
	}
}

// TestPathArchiveExtraction checks the Zip Slip shape: a request-supplied archive's
// stored entry names reach the destination, and whether the extractor validates them
// is a dependency fact, never a name or a guess.
func TestPathArchiveExtraction(t *testing.T) {
	for _, tt := range []struct {
		dir, assessment, declared string
		guard                     []string
	}{
		{"vulnerable", "vulnerable_version", "0.4.7", nil},
		{"fixed", "fixed_version", "0.5.5", []string{"library_entry_check"}},
		{"ranged", "unknown_version", "^0.4.7", nil},
	} {
		t.Run(tt.dir, func(t *testing.T) {
			uses := pathUses(analyzeFixture(t, "javascript/path-traversal-zip/"+tt.dir))
			u, ok := uses["/import"]
			if !ok {
				t.Fatalf("no archive candidate (have %d)", len(uses))
			}
			if _, bundled := uses["/bundled"]; bundled {
				t.Fatal("a constant archive path is not a request-derived archive")
			}
			f := u.Path
			if err := f.Validate(len(u.Dependencies), len(u.Context)); err != nil {
				t.Fatal(err)
			}
			if f.Operation != "adm-zip.extractAllTo" || f.Role != "write" || f.Extractor == nil || f.Extractor.Assessment != tt.assessment || f.Extractor.Declared != tt.declared {
				t.Fatalf("facts: %+v extractor %+v", f, f.Extractor)
			}
			if len(f.Paths) != 1 || f.Paths[0].Operand != analysis.PathSlotArchive || u.Dependencies[f.Paths[0].Dependency].SinkSlot != analysis.PathSlotArchive || !strings.Contains(u.Dependencies[0].Source.Text, "req.files") {
				t.Fatalf("flows: %+v deps %+v", f.Paths, u.Dependencies)
			}
			if got := guardKinds(u); strings.Join(got, ",") != strings.Join(tt.guard, ",") {
				t.Fatalf("guards %v, want %v", got, tt.guard)
			}
			if u.Completeness == nil || len(u.Completeness.Blockers) != 0 || u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("completeness %+v components %+v", u.Completeness, u.Components)
			}
		})
	}
}

func TestPathExpandedChainAndLayout(t *testing.T) {
	r := analyzeFixture(t, "typescript/path-traversal-expanded")
	uses := pathUses(r)
	for _, route := range []string{"/v/middle", "/v/archive-middle", "/v/layout", "/v/layout-spread", "/v/exported-archive-middle", "/panel", "/v/irrelevant-helper-budget"} {
		u, ok := uses[route]
		if !ok {
			t.Errorf("no general path candidate for %s", route)
			continue
		}
		if err := u.Path.Validate(len(u.Dependencies), len(u.Context)); err != nil {
			t.Error(err)
		}
		if len(u.Path.Paths) == 0 {
			t.Errorf("missing request path at %s", route)
		}
		if len(u.Completeness.Blockers) > 0 {
			t.Errorf("%s blockers: %+v", route, u.Completeness.Blockers)
		}
	}
	for route, want := range map[string]string{"/p/layout-allowlist-alias": analysis.PathGuardAllowlist, "/v/layout-gated-blacklist": analysis.PathGuardSubstring} {
		u, ok := uses[route]
		if !ok {
			t.Errorf("missing %s", route)
			continue
		}
		if got := guardKinds(u); len(got) != 1 || got[0] != want {
			t.Errorf("%s guards %v, want %s", route, got, want)
		}
	}
	if u, ok := uses["/u/archive-filter"]; !ok || len(u.Completeness.Blockers) == 0 {
		t.Error("custom file filter must remain an unresolved predecessor")
	}
	for _, route := range []string{"/n/layout-overridden", "/n/layout-constant"} {
		if _, ok := uses[route]; ok {
			t.Errorf("constant/overridden layout should not be a candidate: %s", route)
		}
	}
}
