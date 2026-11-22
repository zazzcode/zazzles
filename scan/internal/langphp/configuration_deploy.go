package langphp

import (
	"strconv"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
)

func (s *phpSet) emitDeploy(out *analysis.AnalysisReport, root string, p *symfonyProject) {
	images := s.projectImages(root)
	s.emitListings(out, root, p, images)
	s.emitDebug(out, root, images)
	s.emitIni(out, root, images)
	s.emitSchedules(out, root, images)
}

func (s *phpSet) emitListings(out *analysis.AnalysisReport, root string, p *symfonyProject, images []deployconf.DockerImage) {
	doc := ""
	if p != nil {
		doc = p.docRoot
	}
	for _, file := range s.deployFiles {
		if !underRoot(root, file) {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		var dirs []deployconf.Directive
		switch {
		case strings.HasSuffix(file, ".htaccess"), strings.HasSuffix(file, ".conf"):
			apache, _ := deployconf.Apache(file, raw)
			nginx, _ := deployconf.Nginx(file, raw)
			dirs = append(apache, nginx...)
		default:
			continue
		}
		document := ""
		for _, d := range dirs {
			if d.Name == "DocumentRoot" && len(d.Values) > 0 {
				document = d.Values[0]
			}
		}
		for _, d := range dirs {
			on := false
			value := ""
			switch d.Name {
			case "Options":
				on = deployconf.Indexes(d.Effective)
				value = strings.Join(d.Values, " ")
			case "autoindex":
				on = len(d.Values) > 0 && strings.EqualFold(d.Values[0], "on")
				if len(d.Values) > 0 {
					value = d.Values[0]
				}
			default:
				continue
			}
			if !on {
				continue
			}
			mapped, served, gaps := s.mapScope(d.Scope, document, doc, images)
			facts := &analysis.ConfigurationFacts{
				Check: analysis.CheckDirectoryListing, Value: value, Scope: mapped,
				Setting: s.lineEvidence(file, "setting", d.Name+" "+value, d.Line),
			}
			facts.Joined = append(facts.Joined, s.lineEvidence(file, "scope_mapping", mapped, d.Line))
			servedText := "no"
			if served {
				servedText = "yes"
			}
			facts.Joined = append(facts.Joined, s.lineEvidence(file, "scope_served", "served "+servedText+" directory "+mapped, d.Line))
			if installed(file, images) || strings.HasSuffix(file, ".htaccess") {
				facts.Joined = append(facts.Joined, s.lineEvidence(file, "config_installed", file, d.Line))
			}
			for _, u := range out.Uses {
				if u.Kind != "file_upload_candidate" || u.Upload == nil || u.Upload.Destination == "" {
					continue
				}
				if !insidePath(u.Upload.Destination, mapped) {
					continue
				}
				facts.Joined = append(facts.Joined, s.lineEvidence(u.Sink.Span.File, "upload_destination", "upload destination "+u.Upload.Destination+" is inside "+mapped, u.Sink.Span.StartLine))
			}
			s.emitConfig(out, root, facts, gaps)
		}
	}
}

func (s *phpSet) mapScope(scope, document, docRoot string, images []deployconf.DockerImage) (string, bool, []analysis.Gap) {
	var gaps []analysis.Gap
	for _, img := range images {
		gaps = append(gaps, gapFrom(img.Gaps)...)
	}
	mapped, ok := projectPath(images, scope)
	if scope == "" {
		mapped, ok = projectPath(images, document)
	}
	if !ok && len(images) == 0 {
		if alt, yes := trailingMatch(scope, docRoot); yes {
			return alt, true, nil
		}
		if scope != "" {
			return scope, false, []analysis.Gap{{Kind: "deploy_mapping_unresolved", Detail: "scope path does not match a project directory"}}
		}
	}
	if !ok {
		if len(gaps) == 0 && scope != "" {
			gaps = append(gaps, analysis.Gap{Kind: "deploy_mapping_unresolved", Detail: "scope path does not match a project directory"})
		}
		return scope, false, gaps
	}
	served := false
	docMapped, docOK := projectPath(images, document)
	switch {
	case document == "" && docRoot != "" && (mapped == docRoot || strings.HasPrefix(mapped, strings.TrimPrefix(docRoot, "./")+"/") || strings.HasSuffix(mapped, "/"+pathBase(docRoot)) || mapped == pathBase(docRoot)):
		served = true
	case docOK && (mapped == docMapped || strings.HasPrefix(mapped, docMapped+"/")):
		served = true
	case document == "" && mapped != "":
		served = true
	}
	return mapped, served, nil
}

func (s *phpSet) emitDebug(out *analysis.AnalysisReport, root string, images []deployconf.DockerImage) {
	chosen, evidence := s.deployedEnv(root, images)
	if chosen == "" {
		return
	}
	keys, gaps := deployconf.EnvKeys(chosen, mustRead(s, chosen))
	if len(gaps) > 0 {
		return
	}
	if keys["APP_ENV"] == "dev" || keys["APP_DEBUG"] == "1" || strings.EqualFold(keys["APP_DEBUG"], "true") {
		value := keys["APP_ENV"]
		if keys["APP_DEBUG"] == "1" || strings.EqualFold(keys["APP_DEBUG"], "true") {
			value = "APP_DEBUG=" + keys["APP_DEBUG"]
		}
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckDebugEnabled, Value: value,
			Setting: s.lineEvidence(chosen, "setting", "APP_ENV="+keys["APP_ENV"], 1),
			Joined:  []analysis.Evidence{evidence},
		}
		s.emitConfig(out, root, facts, nil)
	}
}

func (s *phpSet) deployedEnv(root string, images []deployconf.DockerImage) (string, analysis.Evidence) {
	var placed []deployconf.EnvPlacement
	var placeLine int
	var placeFile string
	for _, img := range images {
		placed = append(placed, img.EnvFiles...)
		if len(img.EnvFiles) > 0 {
			placeLine = img.EnvFiles[len(img.EnvFiles)-1].Line
		}
	}
	for _, file := range s.deployFiles {
		if dockerFile(file) {
			placeFile = file
		}
	}
	// A COPY that lands on .env or .env.local overrides the project file.
	for i := len(placed) - 1; i >= 0; i-- {
		base := pathBase(placed[i].Dst)
		if base != ".env" && base != ".env.local" {
			continue
		}
		src := placed[i].Src
		if root != "." && root != "" && !strings.HasPrefix(src, root+"/") && !strings.Contains(src, "/") {
			src = joinRoot(root, src)
		}
		if s.readable(src) {
			return src, s.lineEvidence(placeFile, "deployed_file", placed[i].Src+" -> "+placed[i].Dst, placed[i].Line)
		}
	}
	project := joinRoot(root, ".env")
	if containsPath(s.configFiles, project) && s.readable(project) && len(placed) == 0 {
		return project, s.lineEvidence(project, "deployed_file", project, 1)
	}
	_ = placeLine
	return "", analysis.Evidence{}
}

func (s *phpSet) emitIni(out *analysis.AnalysisReport, root string, images []deployconf.DockerImage) {
	for _, file := range s.deployFiles {
		if !underRoot(root, file) || pathBase(file) != "php.ini" {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		dirs, _ := deployconf.PHPIni(file, raw)
		session := "session_authenticated: no"
		if s.hasSessionEntry(out, root) {
			session = "session_authenticated: yes"
		}
		for _, d := range dirs {
			val := ""
			if len(d.Values) > 0 {
				val = d.Values[0]
			}
			switch d.Name {
			case "display_errors":
				if !debugOn(val) {
					continue
				}
				facts := &analysis.ConfigurationFacts{
					Check: analysis.CheckDebugEnabled, Value: val,
					Setting: s.lineEvidence(file, "setting", d.Name+"="+val, d.Line),
					Joined:  []analysis.Evidence{s.lineEvidence(file, "deployed_file", file, d.Line)},
				}
				s.emitConfig(out, root, facts, nil)
			case "session.cookie_httponly":
				if !falseLiteral(val) {
					continue
				}
				facts := &analysis.ConfigurationFacts{
					Check: analysis.CheckSessionCookieScript, Value: val,
					Setting: s.lineEvidence(file, "setting", d.Name+"="+val, d.Line),
					Joined:  []analysis.Evidence{s.lineEvidence(file, "session_authenticated", session, d.Line)},
				}
				s.emitConfig(out, root, facts, nil)
			case "session.cookie_secure":
				if !falseLiteral(val) || strings.EqualFold(val, "auto") {
					continue
				}
				facts := &analysis.ConfigurationFacts{
					Check: analysis.CheckSessionCookieTransport, Value: val,
					Setting: s.lineEvidence(file, "setting", d.Name+"="+val, d.Line),
					Joined:  []analysis.Evidence{s.lineEvidence(file, "session_authenticated", session, d.Line)},
				}
				s.emitConfig(out, root, facts, nil)
			}
		}
	}
	_ = images
}

func (s *phpSet) emitSchedules(out *analysis.AnalysisReport, root string, images []deployconf.DockerImage) {
	type job struct {
		deployconf.ScheduleLine
		from string
	}
	var jobs []job
	for _, img := range images {
		for _, line := range img.Schedules {
			jobs = append(jobs, job{line, line.File})
		}
	}
	for _, file := range s.deployFiles {
		if !underRoot(root, file) {
			continue
		}
		base := pathBase(file)
		system := pathBase(pathDir(file)) == "cron.d" || strings.Contains(file, "/cron.d/")
		user := ""
		installed := false
		for _, img := range images {
			for _, inst := range img.CronInstall {
				mapped, _ := projectPath(images, inst.Path)
				if strings.HasSuffix(inst.Path, base) || mapped == file {
					system = false
					user = inst.User
					installed = true
				}
			}
		}
		if !system && !installed && base != "crontab" && !strings.HasSuffix(base, ".cron") && pathBase(pathDir(file)) != "cron.d" {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		for _, line := range deployconf.Cron(file, raw, system || (!installed && pathBase(pathDir(file)) == "cron.d")) {
			if user != "" && line.User == "" {
				line.User = user
			}
			if line.User == "" && !line.System {
				line.User = "root"
				for _, img := range images {
					if img.User != "" {
						line.User = img.User
					}
				}
			}
			jobs = append(jobs, job{line, file})
		}
	}
	for _, job := range jobs {
		if job.User == "" {
			job.User = "root"
		}
		chainFile, chainLine, chainName, owner := s.writableLink(root, job.Command, job.User, images)
		if chainFile == "" {
			continue
		}
		facts := &analysis.ConfigurationFacts{
			Check: analysis.CheckScheduledPrivileged, Value: job.User + " " + job.Command, Scope: "deployment",
			Setting: s.lineEvidence(job.File, "setting", job.User+" runs "+job.Command, job.Line),
			Joined: []analysis.Evidence{
				s.lineEvidence(job.File, "config_installed", "schedule is in the deployment file", job.Line),
				s.lineEvidence(job.File, "schedule", job.User+" runs "+job.Command, job.Line),
				s.lineEvidence(chainFile, "chain", "the scheduled script runs "+chainName, chainLine),
				s.lineEvidence(owner.File, "ownership", owner.User+owner.Mode+" owns "+owner.Path+", not the schedule user "+job.User, owner.Line),
			},
		}
		s.emitConfig(out, root, facts, nil)
	}
}

type chainHit struct {
	file, name, target string
	line               int
}

func (s *phpSet) writableLink(root, command, user string, images []deployconf.DockerImage) (string, int, string, deployconf.Ownership) {
	cwd := "/"
	for _, img := range images {
		if img.WorkDir != "" {
			cwd = img.WorkDir
		}
	}
	rest := command
	if dir, after, ok := strings.Cut(command, "&&"); ok && strings.HasPrefix(strings.TrimSpace(dir), "cd ") {
		cwd = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(dir), "cd "))
		rest = after
	}
	var files []chainHit
	s.addChain(root, cwd, rest, images, &files, true)
	var owners []deployconf.Ownership
	for _, img := range images {
		owners = append(owners, img.Owners...)
	}
	for _, hit := range files {
		check := hit.target
		if check == "" {
			check = hit.file
		}
		container := containerPath(images, check)
		for _, own := range owners {
			if !covers(own, container) && !covers(own, check) && !covers(own, hit.file) {
				continue
			}
			if own.User != "" && own.User == user {
				continue
			}
			if own.User == "" && !modeWrites(own.Mode) {
				continue
			}
			if own.User != "" && !modeWrites(own.Mode) && own.Mode != "" {
				continue
			}
			return hit.file, hit.line, hit.name, own
		}
	}
	return "", 0, "", deployconf.Ownership{}
}

func (s *phpSet) addChain(root, cwd, command string, images []deployconf.DockerImage, files *[]chainHit, follow bool) {
	toks := strings.Fields(command)
	for i, tok := range toks {
		if !looksPath(tok) {
			continue
		}
		container := tok
		if !strings.HasPrefix(tok, "/") {
			container = strings.TrimRight(cwd, "/") + "/" + tok
		}
		proj, ok := projectPath(images, container)
		if !ok {
			proj = strings.TrimPrefix(container, "/")
		}
		if root != "." && root != "" && !strings.HasPrefix(proj, root+"/") {
			proj = joinRoot(root, proj)
		}
		*files = append(*files, chainHit{file: proj, target: proj, line: 1, name: tok})
		if !follow {
			continue
		}
		if i > 0 && (toks[i-1] == "bash" || toks[i-1] == "sh" || toks[i-1] == "php" || strings.HasPrefix(tok, "./")) {
			raw, ok := s.readAllow(proj)
			if !ok {
				continue
			}
			for n, line := range strings.Split(string(raw), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				before := len(*files)
				s.addChain(root, cwd, line, images, files, false)
				for k := before; k < len(*files); k++ {
					if (*files)[k].line == 1 {
						(*files)[k].line = n + 1
						(*files)[k].file = proj
						(*files)[k].target = proj
						if pathArg := pathArgOf(line); pathArg != "" {
							resolved := pathArg
							if !strings.HasPrefix(pathArg, "/") {
								resolved = strings.TrimRight(cwd, "/") + "/" + pathArg
							}
							if p, ok := projectPath(images, resolved); ok {
								(*files)[k].target = p
								(*files)[k].name = pathArg
							}
						}
					}
				}
			}
		}
	}
}

func pathArgOf(line string) string {
	for _, tok := range strings.Fields(line) {
		if looksPath(tok) && tok != "php" && tok != "bash" && tok != "sh" {
			return tok
		}
	}
	return ""
}

func looksPath(tok string) bool {
	if tok == "" || strings.HasPrefix(tok, "-") {
		return false
	}
	return strings.Contains(tok, "/") || strings.HasPrefix(tok, ".")
}

func covers(own deployconf.Ownership, file string) bool {
	p := strings.TrimRight(own.Path, "/")
	f := strings.TrimRight(file, "/")
	if p == "" {
		return false
	}
	if p == f || strings.HasSuffix(f, "/"+strings.TrimPrefix(p, "/")) || strings.HasSuffix(p, "/"+strings.TrimPrefix(f, "/")) {
		return true
	}
	if own.Recursive && (strings.HasPrefix(f, p+"/") || strings.HasPrefix(p, f+"/")) {
		return true
	}
	return false
}

func modeWrites(mode string) bool {
	if strings.Contains(mode, "o+w") || strings.Contains(mode, "g+w") || strings.Contains(mode, "a+w") {
		return true
	}
	if mode == "" {
		return false
	}
	n, err := strconv.ParseUint(mode, 8, 32)
	if err != nil {
		return false
	}
	return n&0o022 != 0
}

func projectPath(images []deployconf.DockerImage, container string) (string, bool) {
	if container == "" {
		return "", false
	}
	best, src := "", ""
	for _, img := range images {
		for dst, from := range img.PathMap {
			if container == dst || strings.HasPrefix(container, strings.TrimRight(dst, "/")+"/") {
				if len(dst) > len(best) {
					best, src = dst, from
				}
			}
		}
	}
	if best == "" {
		return "", false
	}
	rest := strings.TrimPrefix(container, strings.TrimRight(best, "/"))
	rest = strings.TrimPrefix(rest, "/")
	if src == "." || src == "./" || src == "" {
		if rest == "" {
			return ".", true
		}
		return rest, true
	}
	if rest == "" {
		return src, true
	}
	return src + "/" + rest, true
}

func containerPath(images []deployconf.DockerImage, project string) string {
	for _, img := range images {
		for dst, src := range img.PathMap {
			if (src == "." || src == "./") && (project == "." || !strings.HasPrefix(project, "/")) {
				if project == "." {
					return dst
				}
				return strings.TrimRight(dst, "/") + "/" + project
			}
			if project == src || strings.HasPrefix(project, src+"/") {
				rest := strings.TrimPrefix(project, src)
				return strings.TrimRight(dst, "/") + rest
			}
		}
	}
	return project
}

func trailingMatch(scope, docRoot string) (string, bool) {
	scope = strings.Trim(scope, "/")
	doc := strings.Trim(docRoot, "/")
	if doc == "" {
		doc = "public"
	}
	if scope == doc || strings.HasSuffix(scope, "/"+doc) {
		return doc, true
	}
	return "", false
}

func installed(file string, images []deployconf.DockerImage) bool {
	if strings.HasSuffix(file, ".htaccess") {
		return true
	}
	for _, img := range images {
		for _, dst := range img.Installed {
			if strings.Contains(dst, pathBase(file)) {
				return true
			}
		}
	}
	return false
}

func gapFrom(in []deployconf.Gap) []analysis.Gap {
	var out []analysis.Gap
	for _, g := range in {
		out = append(out, analysis.Gap{Kind: g.Kind, Detail: g.Detail, At: analysis.Span{File: g.File, StartLine: g.Line}})
	}
	return out
}

func insidePath(dest, scope string) bool {
	dest = strings.Trim(dest, "/")
	scope = strings.Trim(scope, "/")
	if scope == "" || scope == "." {
		return dest != ""
	}
	return dest == scope || strings.HasPrefix(dest, scope+"/")
}

func debugOn(v string) bool {
	switch strings.ToLower(v) {
	case "on", "1", "stdout":
		return true
	}
	return false
}

func mustRead(s *phpSet, file string) []byte {
	raw, _ := s.readAllow(file)
	return raw
}

func pathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func pathDir(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[:i]
	}
	return "."
}
