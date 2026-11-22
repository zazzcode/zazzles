package langphp

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
)

// finishConfiguration records one candidate per check per setting. It runs
// after entry access and state changes exist.
func (s *phpSet) finishConfiguration(out *analysis.AnalysisReport) {
	for _, file := range s.unreadFiles {
		out.Gaps = append(out.Gaps, analysis.Gap{Kind: "config_file_unread", Detail: "configuration file was not read", At: analysis.Span{File: file, StartLine: 1}})
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

func (s *phpSet) emitConfig(out *analysis.AnalysisReport, root string, facts *analysis.ConfigurationFacts, gaps []analysis.Gap) {
	if facts == nil || facts.Check == "" {
		return
	}
	entryID, invocationID, ok := s.configEntry(out, root)
	if !ok {
		return
	}
	scopeEv := facts.Setting
	scopeEv.Kind = "scope"
	if facts.Scope != "" {
		scopeEv.Text = facts.Scope
		scopeEv.ModelText = facts.Scope
	}
	blockers := []analysis.Gap{}
	for _, g := range gaps {
		if g.Kind == "deploy_mapping_unresolved" || g.Kind == "config_file_unread" {
			blockers = append(blockers, g)
		}
	}
	if blockers == nil {
		blockers = []analysis.Gap{}
	}
	setting := facts.Setting
	out.Uses = append(out.Uses, analysis.CandidateUse{
		ID:      fmt.Sprintf("use:configuration:%s:%d:%s", setting.Span.File, setting.Span.StartLine, facts.Check),
		EntryID: entryID, InvocationContextID: invocationID, Kind: analysis.ConfigurationKind,
		Sink: setting, Configuration: facts, Gaps: append([]analysis.Gap{}, gaps...),
		Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "configuration", Required: []string{"setting", "scope"},
			Evidence: map[string][]analysis.Evidence{"setting": {setting}, "scope": {scopeEv}},
			Blockers: blockers, Coverage: []analysis.Gap{},
			Scope: "One allow-listed setting joined to the application facts that give it meaning. The scanner does not decide that the setting is a defect.",
		},
	})
}

func (s *phpSet) configEntry(out *analysis.AnalysisReport, root string) (string, string, bool) {
	for _, e := range out.Entries {
		if root != "." && root != "" && !underRoot(root, e.Location.Span.File) {
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

func (s *phpSet) lineEvidence(file, kind, text string, line int) analysis.Evidence {
	ev, ok := readSymfonyConfig(s.root, file)
	if !ok {
		ev = analysis.Evidence{Span: analysis.Span{File: file}}
	}
	ev.Kind, ev.Text, ev.ModelText = kind, text, text
	if ev.Span.File == "" {
		ev.Span.File = file
	}
	ev.Span.StartLine, ev.Span.EndLine = line, line
	return ev
}

func (s *phpSet) readAllow(file string) ([]byte, bool) {
	if containsPath(s.unreadFiles, file) {
		return nil, false
	}
	info, err := os.Lstat(filepath.Join(s.root, filepath.FromSlash(file)))
	if err != nil || !info.Mode().IsRegular() || info.Size() > deployconf.MaxFile {
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(s.root, filepath.FromSlash(file)))
	return raw, err == nil
}

func (s *phpSet) readable(file string) bool {
	_, ok := s.readAllow(file)
	return ok
}

func joinRoot(root, rel string) string {
	if root == "." || root == "" {
		return rel
	}
	return path.Join(root, rel)
}

func underRoot(root, file string) bool {
	if root == "." || root == "" {
		return true
	}
	return file == root || strings.HasPrefix(file, root+"/")
}

func containsPath(list []string, file string) bool {
	for _, item := range list {
		if item == file {
			return true
		}
	}
	return false
}

func dockerFile(file string) bool {
	base := path.Base(file)
	return base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

func (s *phpSet) projectImages(root string) []deployconf.DockerImage {
	var out []deployconf.DockerImage
	for _, file := range s.deployFiles {
		if !underRoot(root, file) || !dockerFile(file) {
			continue
		}
		raw, ok := s.readAllow(file)
		if !ok {
			continue
		}
		img := deployconf.Dockerfile(file, raw)
		img.WorkDir = img.WorkDir // keep
		out = append(out, img)
	}
	return out
}

func (s *phpSet) sessionEntries(out *analysis.AnalysisReport, root string) []analysis.EntryPoint {
	var got []analysis.EntryPoint
	for _, e := range out.Entries {
		if e.Access == nil || e.Access.Authentication != analysis.AccessRequired || len(e.StateChanges) == 0 {
			continue
		}
		if !underRoot(root, e.Location.Span.File) {
			continue
		}
		got = append(got, e)
	}
	for i := 1; i < len(got); i++ {
		for j := i; j > 0 && got[j].Name < got[j-1].Name; j-- {
			got[j], got[j-1] = got[j-1], got[j]
		}
	}
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

func (s *phpSet) csrfMitigations(root string) []analysis.Evidence {
	var out []analysis.Evidence
	for _, file := range s.files {
		if !underRoot(root, file) {
			continue
		}
		m := s.modules[file]
		if m == nil || m.tree == nil {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			switch n.Kind() {
			case "function_call_expression", "member_call_expression", "scoped_call_expression":
				if strings.EqualFold(phpText(m, phpField(n, "name")), "isCsrfTokenValid") {
					out = append(out, m.evidence("mitigation", n))
				}
			case "array_element_initializer":
				if n.NamedChildCount() >= 1 {
					key, ok := phpStringLiteral(m, n.NamedChild(0))
					if ok && key == "csrf_token_id" {
						out = append(out, m.evidence("mitigation", n))
					}
				}
			}
		})
	}
	return out
}

func (s *phpSet) iniSetCookie(root, key string) []analysis.Evidence {
	var out []analysis.Evidence
	for _, file := range s.files {
		if !underRoot(root, file) {
			continue
		}
		m := s.modules[file]
		if m == nil || m.tree == nil {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "function_call_expression" {
				return
			}
			if !strings.EqualFold(strings.TrimPrefix(phpText(m, phpField(n, "function")), `\`), "ini_set") {
				return
			}
			args := phpArgs(n)
			if len(args) < 2 {
				return
			}
			name, ok := phpStringLiteral(m, args[0])
			if !ok || name != key {
				return
			}
			val, ok := phpStringLiteral(m, args[1])
			if !ok || !falseLiteral(val) {
				return
			}
			out = append(out, m.evidence("setting", n))
		})
	}
	return out
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

// projectInstalled reports that a project file is part of the deployed tree.
func (s *phpSet) projectInstalled(root, file string, images []deployconf.DockerImage) (analysis.Evidence, bool) {
	for _, img := range images {
		for dst, src := range img.PathMap {
			if src == "." || src == "./" || file == src || strings.HasPrefix(file, strings.TrimPrefix(src, "./")+"/") {
				docker := ""
				for _, name := range s.deployFiles {
					if underRoot(root, name) && dockerFile(name) {
						docker = name
						break
					}
				}
				if docker == "" {
					docker = file
				}
				return s.lineEvidence(docker, "config_installed", "copied "+src+" to "+dst+" including "+file, 1), true
			}
		}
	}
	if len(images) == 0 {
		return s.lineEvidence(file, "config_installed", file, 1), true
	}
	return analysis.Evidence{}, false
}
