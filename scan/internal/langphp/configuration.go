package langphp

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
	"github.com/zazzcode/zazzles/scan/internal/walk"
)

// finishConfiguration records one candidate per check per setting. It runs
// after entry access and state changes exist.
func (s *phpSet) finishConfiguration(out *analysis.AnalysisReport) {
	for _, file := range s.unreadFiles {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "configuration file was not read", At: analysis.Span{File: file, StartLine: 1}})
	}
	for _, list := range s.truncatedLists {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_list_truncated", Detail: "the " + list + " file list passed 200 files; the files after the limit were not read"})
	}
	if len(s.symfony) == 0 {
		s.emitDeploy(out, ".", nil)
		return
	}
	for _, p := range s.symfony {
		s.emitSymfonyChecks(out, p)
		s.emitDeploy(out, p.root, p)
	}
}

// emitConfig records one candidate. scope is the evidence of the setting's
// real scope: a directory block, a project manifest, a deployment file. A
// candidate without it keeps the role empty, and the policy then holds the
// claim for evidence.
func (s *phpSet) emitConfig(out *analysis.AnalysisReport, root string, facts *analysis.ConfigurationFacts, scope analysis.Evidence, gaps []analysis.Gap) {
	setting := facts.Setting
	entryID, invocationID, ok := s.configEntry(out, root)
	if !ok {
		// A candidate rides an invocation context. Without one the setting is
		// stated as a gap, so it does not vanish.
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "configuration_entry_missing", Detail: "setting " + facts.Check + " was read, and the project has no entry to report it under", At: setting.Span})
		return
	}
	evidence := map[string][]analysis.Evidence{"setting": {setting}}
	if scope.Span.File != "" {
		scope.Kind = "scope"
		evidence["scope"] = []analysis.Evidence{scope}
	}
	blockers := []analysis.Gap{}
	for _, g := range gaps {
		if g.Kind == "deploy_mapping_unresolved" || g.Kind == "config_file_unread" {
			blockers = append(blockers, g)
		}
	}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		ID:      fmt.Sprintf("use:configuration:%s:%d:%s", setting.Span.File, setting.Span.StartLine, facts.Check),
		EntryID: entryID, InvocationContextID: invocationID, Kind: analysis.ConfigurationKind,
		Sink: setting, Configuration: facts, Gaps: append([]analysis.Gap{}, gaps...),
		Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "configuration", Required: []string{"setting", "scope"},
			Evidence: evidence, Blockers: blockers, Coverage: []analysis.Gap{},
			Scope: "One allow-listed setting joined to the application facts that give it meaning. The scanner does not decide that the setting is a defect.",
		},
	})
}

func (s *phpSet) configEntry(out *analysis.AnalysisReport, root string) (string, string, bool) {
	for _, e := range out.Entries {
		if !underRoot(root, e.Location.Span.File) {
			continue
		}
		for _, c := range out.InvocationContexts {
			if c.EntryID == e.ID {
				return e.ID, c.ID, true
			}
		}
	}
	if len(out.Entries) == 0 || len(out.InvocationContexts) == 0 {
		return "", "", false
	}
	return out.Entries[0].ID, out.InvocationContexts[0].ID, true
}

// containedPath returns the absolute path of a scan-relative file when the
// path stays inside the scan root, names no skipped directory and no
// project var/ directory, and crosses no symbolic link.
func (s *phpSet) containedPath(file string) (string, os.FileInfo, bool) {
	file = path.Clean(filepath.ToSlash(file))
	if file == "." || path.IsAbs(file) || file == ".." || strings.HasPrefix(file, "../") {
		return "", nil, false
	}
	abs := s.root
	dir := "."
	var info os.FileInfo
	for _, part := range strings.Split(file, "/") {
		if slices.Contains(walk.DefaultSkipDirs, part) {
			return "", nil, false
		}
		if _, project := s.composers[dir]; project && part == "var" {
			return "", nil, false
		}
		abs = filepath.Join(abs, part)
		dir = path.Join(dir, part)
		var err error
		if info, err = os.Lstat(abs); err != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", nil, false
		}
	}
	return abs, info, true
}

// textFile is one contained file read once for the whole scan.
type textFile struct {
	evidence analysis.Evidence
	ok       bool
}

// fileText reads a regular file inside the scan root, at most 1 MiB, and
// keeps it, so every setting of the file shares one read and one hash.
func (s *phpSet) fileText(file string) (analysis.Evidence, bool) {
	if got, ok := s.textFiles[file]; ok {
		return got.evidence, got.ok
	}
	var got textFile
	if _, info, ok := s.containedPath(file); ok && info.Mode().IsRegular() {
		got.evidence, got.ok = readSymfonyConfig(s.root, file)
	}
	if s.textFiles == nil {
		s.textFiles = map[string]textFile{}
	}
	s.textFiles[file] = got
	return got.evidence, got.ok
}

// readAllow reads an allow-listed configuration or deployment file within
// the 256 KiB limit. A path taken from a deployment file goes through the
// same containment as a walked one.
func (s *phpSet) readAllow(file string) ([]byte, bool) {
	if slices.Contains(s.unreadFiles, file) {
		return nil, false
	}
	ev, ok := s.fileText(file)
	if !ok || len(ev.Text) > deployconf.MaxFile {
		return nil, false
	}
	return []byte(ev.Text), true
}

func (s *phpSet) isDir(file string) bool {
	_, info, ok := s.containedPath(file)
	return ok && info.IsDir()
}

// lineEvidence is evidence at one line of a contained text file. Its byte
// span is that line, so two settings of one file are two places.
func (s *phpSet) lineEvidence(file, kind, text string, line int) analysis.Evidence {
	ev, ok := s.fileText(file)
	if !ok {
		ev = analysis.Evidence{Span: analysis.Span{File: file}}
	}
	start, end := lineBytes(ev.Text, line)
	ev.Kind, ev.Text, ev.ModelText = kind, text, text
	ev.Span.StartLine, ev.Span.EndLine = line, line
	ev.Span.StartByte, ev.Span.EndByte = start, end
	return ev
}

// lineBytes returns the byte range of a 1-based line of text, without its
// line break. A line past the end is the empty range at the end.
func lineBytes(text string, line int) (int, int) {
	start := 0
	for n := 1; n < line; n++ {
		i := strings.IndexByte(text[start:], '\n')
		if i < 0 {
			return len(text), len(text)
		}
		start += i + 1
	}
	if i := strings.IndexByte(text[start:], '\n'); i >= 0 {
		return start, start + i
	}
	return start, len(text)
}

func joinRoot(root, rel string) string {
	if root == "." || root == "" {
		return path.Clean(rel)
	}
	return path.Join(root, rel)
}

func underRoot(root, file string) bool {
	if root == "." || root == "" {
		return true
	}
	return file == root || strings.HasPrefix(file, root+"/")
}

// relRoot returns file relative to a project root.
func relRoot(root, file string) string {
	if root == "." || root == "" {
		return file
	}
	if file == root {
		return "."
	}
	return strings.TrimPrefix(file, root+"/")
}

func dockerFile(file string) bool {
	base := path.Base(file)
	return base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

// deployView is one project's deployment files, each parsed once.
type deployView struct {
	set    *phpSet
	root   string
	images []deployconf.DockerImage
	web    []webConf
	// webUnread is set when a listed web-server file could not be read.
	webUnread bool
}

// webConf is the directives of one .conf or .htaccess file. A file is read
// with both readers, because its name does not say which server it is for.
type webConf struct {
	file       string
	directives []deployconf.Directive
}

func (s *phpSet) deployment(root string) *deployView {
	if v, ok := s.deployViews[root]; ok {
		return v
	}
	v := &deployView{set: s, root: root}
	for _, file := range s.deployFiles {
		if !underRoot(root, file) {
			continue
		}
		web := strings.HasSuffix(file, ".conf") || path.Base(file) == ".htaccess"
		if !web && !dockerFile(file) {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			v.webUnread = v.webUnread || web
			continue
		}
		if web {
			apache, _ := deployconf.Apache(file, raw)
			nginx, _ := deployconf.Nginx(file, raw)
			v.web = append(v.web, webConf{file: file, directives: append(apache, nginx...)})
			continue
		}
		v.images = append(v.images, deployconf.Dockerfile(file, raw, func(src string) bool { return s.isDir(joinRoot(root, src)) }))
	}
	if s.deployViews == nil {
		s.deployViews = map[string]*deployView{}
	}
	s.deployViews[root] = v
	return v
}

// projectPath maps a container path to a scan-relative project path through
// the first image that copies it.
func (v *deployView) projectPath(container string) (string, bool) {
	if container == "" {
		return "", false
	}
	for _, img := range v.images {
		if p, ok := img.ProjectPath(container); ok {
			return joinRoot(v.root, p), true
		}
	}
	return "", false
}

// trailingDir matches a container directory to a project directory by its
// trailing path segments, longest first. It is the mapping of a project
// with no Dockerfile.
func (v *deployView) trailingDir(container string) (string, bool) {
	parts := strings.Split(strings.Trim(path.Clean(container), "/"), "/")
	for i := 1; i < len(parts); i++ {
		if dir := joinRoot(v.root, path.Join(parts[i:]...)); v.set.isDir(dir) {
			return dir, true
		}
	}
	return "", false
}

// mappingGaps are the unresolved operands of the project's images.
func (v *deployView) mappingGaps() []analysis.Gap {
	var out []analysis.Gap
	for _, img := range v.images {
		for _, g := range img.Gaps {
			out = append(out, analysis.Gap{Kind: g.Kind, Detail: g.Detail, At: analysis.Span{File: g.File, StartLine: g.Line}})
		}
	}
	return out
}

// installed returns the COPY that places a project file under a web-server
// configuration directory.
func (v *deployView) installed(file string) (analysis.Evidence, bool) {
	for _, img := range v.images {
		if line, ok := img.Installed(relRoot(v.root, file)); ok {
			return v.set.lineEvidence(img.File, "config_installed", file+" is copied into the web server configuration", line), true
		}
	}
	return analysis.Evidence{}, false
}

// shipped reports that a project file is part of the deployed tree: a COPY
// takes it or a directory above it, or the project has no Dockerfile.
func (v *deployView) shipped(file string) (analysis.Evidence, bool) {
	if len(v.images) == 0 {
		return v.set.lineEvidence(file, "config_installed", file, 1), true
	}
	rel := relRoot(v.root, file)
	for _, img := range v.images {
		for _, m := range img.Paths {
			if m.Src == "." || rel == m.Src || strings.HasPrefix(rel, m.Src+"/") {
				return v.set.lineEvidence(img.File, "config_installed", "copied "+m.Src+" to "+m.Dst+" including "+file, m.Line), true
			}
		}
	}
	return analysis.Evidence{}, false
}

// projectScope is the scope evidence of a project-wide setting.
func (s *phpSet) projectScope(p *symfonyProject) analysis.Evidence {
	if p == nil {
		return analysis.Evidence{}
	}
	return s.lineEvidence(p.composerSpan.File, "scope", "project "+p.root, p.composerSpan.StartLine)
}

func (s *phpSet) sessionEntries(out *analysis.AnalysisReport, root string) []analysis.EntryPoint {
	var got []analysis.EntryPoint
	for _, e := range out.Entries {
		if e.Access != nil && e.Access.Authentication == analysis.AccessRequired && len(e.StateChanges) > 0 && underRoot(root, e.Location.Span.File) {
			got = append(got, e)
		}
	}
	slices.SortStableFunc(got, func(a, b analysis.EntryPoint) int { return strings.Compare(a.Name, b.Name) })
	if len(got) > 8 {
		got = got[:8]
	}
	return got
}

func (s *phpSet) hasSessionEntry(out *analysis.AnalysisReport, root string) bool {
	for _, e := range out.Entries {
		if e.Access != nil && e.Access.Authentication == analysis.AccessRequired && underRoot(root, e.Location.Span.File) {
			return true
		}
	}
	return false
}

func (s *phpSet) sessionJoin(out *analysis.AnalysisReport, root, file string, line int) analysis.Evidence {
	text := "session_authenticated: no"
	if s.hasSessionEntry(out, root) {
		text = "session_authenticated: yes"
	}
	return s.lineEvidence(file, "session_authenticated", text, line)
}

func falseLiteral(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "off", "":
		return true
	}
	return false
}

func entryJoin(e analysis.EntryPoint) string {
	name := e.Name
	if name == "" && e.HTTP != nil {
		name = strings.TrimSpace(e.HTTP.Method + " " + e.HTTP.Path)
	}
	if e.Access != nil && e.Access.Authentication == analysis.AccessRequired {
		name += " authentication required"
	}
	return name
}
