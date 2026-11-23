package langphp

import (
	"path"
	"slices"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
)

func (s *phpSet) emitDeploy(out *analysis.AnalysisReport, root string, p *symfonyProject) {
	v := s.deployment(root)
	s.emitListings(out, v, p)
	s.emitDebug(out, v)
	s.emitIni(out, v)
	s.emitSchedules(out, v)
}

// listingScope is where a listing directive applies, as a project directory.
type listingScope struct {
	dir      string
	mapped   bool
	served   bool
	evidence analysis.Evidence
	gaps     []analysis.Gap
}

func (s *phpSet) emitListings(out *analysis.AnalysisReport, v *deployView, p *symfonyProject) {
	for _, conf := range v.web {
		for _, d := range conf.directives {
			value := strings.Join(d.Values, " ")
			switch {
			case d.Name == "Options" && deployconf.Indexes(d.Effective):
			case d.Name == "autoindex" && strings.EqualFold(value, "on"):
			default:
				continue
			}
			sc := v.listingScope(conf, d, p)
			facts := &analysis.ConfigurationFacts{
				Check: analysis.CheckDirectoryListing, Value: value, Scope: sc.dir,
				Setting: s.lineEvidence(conf.file, "setting", d.Name+" "+value, d.Line),
			}
			served := "no"
			if sc.served {
				served = "yes"
			}
			facts.Joined = append(facts.Joined,
				s.lineEvidence(conf.file, "scope_mapping", sc.dir, d.Line),
				s.lineEvidence(conf.file, "scope_served", "served "+served+" directory "+sc.dir, d.Line))
			if path.Base(conf.file) == ".htaccess" {
				if sc.served {
					facts.Joined = append(facts.Joined, s.lineEvidence(conf.file, "config_installed", conf.file+" is under the document root", 1))
				}
			} else if ev, ok := v.installed(conf.file); ok {
				facts.Joined = append(facts.Joined, ev)
			}
			for _, u := range out.Uses {
				if sc.mapped && u.Kind == "file_upload_candidate" && u.Upload != nil && insidePath(u.Upload.Destination, sc.dir) {
					facts.Joined = append(facts.Joined, s.lineEvidence(u.Sink.Span.File, "upload_destination", "upload destination "+u.Upload.Destination+" is inside "+sc.dir, u.Sink.Span.StartLine))
				}
			}
			s.emitConfig(out, v.root, facts, sc.evidence, sc.gaps)
		}
	}
}

// documentRoot returns the project directory the web server serves and the
// evidence for it: a DocumentRoot or server-level root that maps to the
// project, else the framework's public directory, else the project root,
// which plain PHP serves whole.
func (v *deployView) documentRoot(conf webConf, p *symfonyProject) (string, analysis.Evidence) {
	stated := func(directives []deployconf.Directive) (string, analysis.Evidence, bool) {
		for _, d := range directives {
			if (d.Name != "DocumentRoot" && d.Name != "root") || d.Scope != "" || len(d.Values) == 0 {
				continue
			}
			if dir, ok := v.containerDir(d.Values[0]); ok {
				return dir, v.set.lineEvidence(d.File, "scope", d.Name+" "+d.Values[0], d.Line), true
			}
		}
		return "", analysis.Evidence{}, false
	}
	if dir, ev, ok := stated(conf.directives); ok {
		return dir, ev
	}
	// Another file of the project may state the root, as a virtual host
	// file does beside a per-directory file. One distinct value is used.
	found, evidence := "", analysis.Evidence{}
	for _, other := range v.web {
		dir, ev, ok := stated(other.directives)
		if !ok {
			continue
		}
		if found != "" && found != dir {
			found = ""
			break
		}
		found, evidence = dir, ev
	}
	if found != "" {
		return found, evidence
	}
	if p != nil {
		return p.docRoot, v.set.projectScope(p)
	}
	return joinRoot(v.root, "."), analysis.Evidence{}
}

// containerDir maps a container directory to a project directory through
// the images, or by trailing segments when the project has no Dockerfile.
func (v *deployView) containerDir(container string) (string, bool) {
	if dir, ok := v.projectPath(container); ok {
		return dir, true
	}
	if len(v.images) == 0 {
		return v.trailingDir(container)
	}
	return "", false
}

func (v *deployView) listingScope(conf webConf, d deployconf.Directive, p *symfonyProject) listingScope {
	docDir, docEvidence := v.documentRoot(conf, p)
	if path.Base(conf.file) == ".htaccess" {
		// An .htaccess scope is already a project directory.
		return listingScope{dir: d.Scope, mapped: true, served: insidePath(d.Scope, docDir),
			evidence: v.set.lineEvidence(conf.file, "scope", d.Scope, 1)}
	}
	container := d.Scope
	if d.Name == "autoindex" {
		container = d.Dir
	}
	if container == "" && d.Scope == "" {
		// Server scope with no stated root: the document root.
		return listingScope{dir: docDir, mapped: true, served: true, evidence: docEvidence}
	}
	line := d.ScopeLine
	if line == 0 {
		line = d.Line
	}
	unresolved := func(text string) listingScope {
		gaps := append(v.mappingGaps(), analysis.Gap{Kind: "deploy_mapping_unresolved", Detail: "scope path does not match a project directory", At: analysis.Span{File: conf.file, StartLine: line}})
		return listingScope{dir: text, gaps: gaps, evidence: v.set.lineEvidence(conf.file, "scope", text, line)}
	}
	if container == "" {
		return unresolved(d.Scope)
	}
	dir, ok := v.containerDir(container)
	if !ok {
		return unresolved(container)
	}
	return listingScope{dir: dir, mapped: true, served: insidePath(dir, docDir),
		evidence: v.set.lineEvidence(conf.file, "scope", container, line)}
}

// insidePath reports that dest is scope or lies under it. Both are project
// paths, with or without a leading slash.
func insidePath(dest, scope string) bool {
	dest, scope = strings.Trim(dest, "/"), strings.Trim(scope, "/")
	if dest == "" {
		return false
	}
	return scope == "" || scope == "." || dest == scope || strings.HasPrefix(dest, scope+"/")
}

// envSource is one kept environment key and the file that sets it.
type envSource struct {
	deployconf.EnvSetting
	file     string
	deployed analysis.Evidence
}

// deployedEnv returns APP_ENV and APP_DEBUG as the deployed application
// reads them: the project's .env, then .env.local over it, then each file a
// COPY places at the project root under one of those names, in order. ok
// is false when a placed file could not be read, because the values in
// force are then unknown.
func (s *phpSet) deployedEnv(v *deployView) (map[string]envSource, bool) {
	keys := map[string]envSource{}
	apply := func(file string, deployed analysis.Evidence, replace bool) bool {
		raw, ok := s.readAllow(file)
		if !ok {
			return false
		}
		got, gaps := deployconf.EnvKeys(file, raw)
		if len(gaps) > 0 {
			return false
		}
		if replace {
			clear(keys)
		}
		for key, setting := range got {
			keys[key] = envSource{EnvSetting: setting, file: file, deployed: deployed}
		}
		return true
	}
	for _, name := range []string{".env", ".env.local"} {
		file := joinRoot(v.root, name)
		if !slices.Contains(s.configFiles, file) {
			continue
		}
		if _, shipped := v.shipped(file); shipped {
			apply(file, s.lineEvidence(file, "deployed_file", file, 1), name == ".env")
		}
	}
	for _, img := range v.images {
		for _, m := range img.EnvFiles {
			base := path.Base(m.Dst)
			if base != ".env" && base != ".env.local" {
				continue
			}
			if dir, ok := v.projectPath(path.Dir(m.Dst)); ok && dir != joinRoot(v.root, ".") {
				continue
			}
			deployed := s.lineEvidence(img.File, "deployed_file", m.Src+" -> "+m.Dst, m.Line)
			if !apply(joinRoot(v.root, m.Src), deployed, base == ".env") {
				return nil, false
			}
		}
	}
	return keys, true
}

func (s *phpSet) emitDebug(out *analysis.AnalysisReport, v *deployView) {
	keys, ok := s.deployedEnv(v)
	if !ok {
		return
	}
	for _, key := range []string{"APP_DEBUG", "APP_ENV"} {
		src, set := keys[key]
		on := set && (key == "APP_ENV" && src.Value == "dev" || key == "APP_DEBUG" && (src.Value == "1" || strings.EqualFold(src.Value, "true")))
		if !on {
			continue
		}
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckDebugEnabled, Value: src.Value, Scope: "deployment",
			Setting: s.lineEvidence(src.file, "setting", key+"="+src.Value, src.Line),
			Joined:  []analysis.Evidence{src.deployed},
		}
		s.emitConfig(out, v.root, facts, src.deployed, nil)
	}
}

func (s *phpSet) emitIni(out *analysis.AnalysisReport, v *deployView) {
	for _, file := range s.deployFiles {
		if !underRoot(v.root, file) || path.Base(file) != "php.ini" {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		scope := s.lineEvidence(file, "scope", "deployment file "+file, 1)
		for _, img := range v.images {
			for _, m := range img.Paths {
				if m.Src == relRoot(v.root, file) {
					scope = s.lineEvidence(img.File, "scope", file+" is copied to "+m.Dst, m.Line)
				}
			}
		}
		dirs, _ := deployconf.PHPIni(file, raw)
		for _, d := range dirs {
			val := d.Values[0]
			facts := &analysis.ConfigurationFacts{Value: val, Scope: "deployment", Setting: s.lineEvidence(file, "setting", d.Name+"="+val, d.Line)}
			switch {
			case d.Name == "display_errors" && debugOn(val):
				facts.Check = analysis.CheckDebugEnabled
				facts.Joined = []analysis.Evidence{s.lineEvidence(file, "deployed_file", file, d.Line)}
			case d.Name == "session.cookie_httponly" && falseLiteral(val):
				facts.Check = analysis.CheckSessionCookieScript
				facts.Joined = []analysis.Evidence{s.sessionJoin(out, v.root, file, d.Line)}
			case d.Name == "session.cookie_secure" && falseLiteral(val):
				facts.Check = analysis.CheckSessionCookieTransport
				facts.Joined = []analysis.Evidence{s.sessionJoin(out, v.root, file, d.Line)}
			default:
				continue
			}
			s.emitConfig(out, v.root, facts, scope, nil)
		}
	}
}

func debugOn(v string) bool {
	switch strings.ToLower(v) {
	case "on", "1", "stdout":
		return true
	}
	return false
}
