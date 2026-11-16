package parse

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// nextProject is one Next.js application root found in the scan: the nearest
// manifest declaring `next`, or a directory holding a next.config file.
type nextProject struct {
	dir                 string // scan-root relative, "" for the root
	appDir, pagesDir    string // routable directories, "" when absent
	config              string // next.config.* file, "" when absent
	nextVersion, reactV string
	nextMajor           int // 0 when unknown
	manifest            string
	excluded            []string // tsconfig exclude entries applied to automatic selection
	middleware          string   // middleware.ts / proxy.ts file
}

// webOrigin is the acquisition fact a web-request read established for one
// source span. It is recorded where the flow creates the source and read back
// when shared input facts are assembled.
type webOrigin struct {
	origin, initialType, field string
}

// nextState holds the Next.js adapter's per-scan facts.
type nextState struct {
	projects []*nextProject
	origins  map[string]webOrigin
	// classes is the execution class of each module (next_modules.go).
	classes map[string]string
	// excludedFiles were removed from automatic selection by a project tsconfig.
	excludedFiles []string
	routeFiles    map[string]bool
	// clientRequests are browser requests made through verified helpers or fetch.
	clientRequests []clientRequest
}

func spanKey(s analysis.Span) string {
	return s.File + ":" + strconv.Itoa(s.StartByte) + ":" + strconv.Itoa(s.EndByte)
}

// wireInputType maps a web-request value type onto the input_facts v1 type
// vocabulary. Nullability is absence, not an attacker-chosen type, so
// `string | null` is a string; anything without a fixed JSON shape is unknown.
func wireInputType(t string) string {
	switch t {
	case "string", "string | null", "RequestCookie | undefined":
		if t == "RequestCookie | undefined" {
			return "object"
		}
		return "string"
	case "string[]", "string[] | undefined":
		return "array"
	case "object", "URLSearchParams", "FormData", "URL", "iterable":
		return "object"
	}
	return "unknown"
}

func (s *moduleSet) recordWebOrigin(e analysis.Evidence, o webOrigin) {
	o.initialType = wireInputType(o.initialType)
	if s.next == nil {
		s.next = &nextState{}
	}
	if s.next.origins == nil {
		s.next.origins = map[string]webOrigin{}
	}
	s.next.origins[spanKey(e.Span)] = o
}

func (s *moduleSet) webOriginFor(e analysis.Evidence) (webOrigin, bool) {
	if s.next == nil || s.next.origins == nil {
		return webOrigin{}, false
	}
	o, ok := s.next.origins[spanKey(e.Span)]
	return o, ok
}

var nextConfigNames = []string{"next.config.ts", "next.config.mjs", "next.config.js", "next.config.cjs", "next.config.mts"}

// detectNextProjects finds Next.js roots among the selected JS/TS files. A root
// needs a manifest that declares `next` (dependencies only) or a next.config
// file; routable directories come from the files that exist under it.
func (s *moduleSet) detectNextProjects(files []string) {
	if s.next == nil {
		s.next = &nextState{}
	}
	candidates := map[string]bool{}
	for _, f := range files {
		base := path.Base(f)
		for _, name := range nextConfigNames {
			if base == name {
				candidates[cleanRel(path.Dir(f))] = true
			}
		}
	}
	// Probe the root manifest without recording it as evidence: a scan that has
	// no Next.js project must not gain a file record from this check.
	if rootDeclaresNext(s.root) {
		candidates[""] = true
	}
	dirs := make([]string, 0, len(candidates))
	for d := range candidates {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		probe := joinDir(dir, "x")
		declared, manifest := s.declaration(probe, "next")
		p := &nextProject{dir: dir, manifest: manifest}
		if declared == "" {
			// A next.config without a declared dependency is still a project, but
			// every version-dependent fact stays unknown.
			p.manifest = ""
		}
		p.nextVersion = s.packageVersion(probe, "next")
		p.reactV = s.packageVersion(probe, "react")
		p.nextMajor = semverMajor(p.nextVersion)
		for _, name := range nextConfigNames {
			if s.allowed[joinDir(dir, name)] {
				p.config = joinDir(dir, name)
				break
			}
		}
		has := func(prefix string) bool {
			for _, f := range files {
				if strings.HasPrefix(f, prefix+"/") {
					return true
				}
			}
			return false
		}
		for _, cand := range []string{"app", "src/app"} {
			if has(joinDir(dir, cand)) {
				p.appDir = joinDir(dir, cand)
				break
			}
		}
		for _, cand := range []string{"pages", "src/pages"} {
			if has(joinDir(dir, cand)) {
				p.pagesDir = joinDir(dir, cand)
				break
			}
		}
		for _, cand := range []string{"middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js", "proxy.ts", "proxy.js", "src/proxy.ts", "src/proxy.js"} {
			if s.allowed[joinDir(dir, cand)] {
				p.middleware = joinDir(dir, cand)
				break
			}
		}
		if p.appDir == "" && p.pagesDir == "" && p.config == "" {
			continue
		}
		if cfg := s.tsConfigFor(joinDir(dir, "x")); cfg != nil && cfg.hasExcl && cfg.dir == dir {
			p.excluded = cfg.exclude
		}
		s.next.projects = append(s.next.projects, p)
	}
}

func semverMajor(v string) int {
	v = strings.TrimLeft(v, "^~>=v ")
	if i := strings.IndexByte(v, '.'); i > 0 {
		v = v[:i]
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return n
}

// nextProjectFor returns the deepest project containing file.
func (s *moduleSet) nextProjectFor(file string) *nextProject {
	if s.next == nil {
		return nil
	}
	var best *nextProject
	for _, p := range s.next.projects {
		if p.dir == "" || strings.HasPrefix(file, p.dir+"/") {
			if best == nil || len(p.dir) > len(best.dir) {
				best = p
			}
		}
	}
	return best
}

// nextExcluded reports a file a Next project's own tsconfig `exclude` removes.
// Only directory and file entries are applied; glob entries other than a
// trailing "/**" or "/*" are ignored rather than guessed.
func (p *nextProject) nextExcluded(file string) bool {
	rel := file
	if p.dir != "" {
		if !strings.HasPrefix(file, p.dir+"/") {
			return false
		}
		rel = strings.TrimPrefix(file, p.dir+"/")
	}
	for _, e := range p.excluded {
		e = strings.TrimPrefix(strings.TrimSuffix(strings.TrimSuffix(e, "/**"), "/*"), "./")
		e = strings.TrimSuffix(e, "/")
		if e == "" || strings.ContainsAny(e, "*?[{") {
			continue
		}
		if rel == e || strings.HasPrefix(rel, e+"/") {
			return true
		}
	}
	return false
}

// applyNextScope removes files excluded by a Next project's tsconfig from the
// automatically selected registration files and from module resolution. An
// explicit --entry is never filtered. The removals are reported as one gap per
// excluded top-level directory so nothing disappears silently.
func (s *moduleSet) applyNextScope(out *analysis.AnalysisReport, selected []string) []string {
	if s.next == nil || len(s.next.projects) == 0 {
		return selected
	}
	kept := selected[:0:0]
	counts := map[string]int{}
	for _, f := range selected {
		p := s.nextProjectFor(f)
		if p != nil && p.nextExcluded(f) {
			delete(s.allowed, f)
			s.next.excludedFiles = append(s.next.excludedFiles, f)
			rel := strings.TrimPrefix(f, p.dir+"/")
			top := strings.SplitN(rel, "/", 2)[0]
			counts[joinDir(p.dir, top)]++
			continue
		}
		kept = append(kept, f)
	}
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "next_scope_excluded", Detail: strconv.Itoa(counts[k]) + " JS/TS files under " + k + " excluded by the Next.js project's tsconfig.json exclude", At: analysis.Span{File: k}})
	}
	return kept
}

func rootDeclaresNext(root string) bool {
	src, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil || len(src) > maxPackageFileBytes {
		return false
	}
	var manifest struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	return json.Unmarshal(src, &manifest) == nil && manifest.Dependencies["next"] != ""
}
