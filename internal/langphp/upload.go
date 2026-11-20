package langphp

import (
	"path"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

// PHP upload facts (close-findings-gaps W5, D-19 to D-21).
var (
	phpContentSniff = regexp.MustCompile(`\b(getimagesize|finfo_file|finfo_buffer|mime_content_type|exif_imagetype)\s*\(`)
	phpReEncode     = regexp.MustCompile(`\bimage(jpeg|png|gif|webp)\s*\(|\bimagecreatefrom\w+\s*\(`)
	phpLiteralTest  = regexp.MustCompile(`(==|===|!=|!==)\s*['"][\w.+/-]{1,32}['"]|['"][\w.+/-]{1,32}['"]\s*(==|===|!=|!==)|\bin_array\s*\(`)
	phpExtension    = regexp.MustCompile(`\.[A-Za-z0-9]{1,8}$`)
)

// phpUploadProjection reports a $_FILES dependency projected to field.
func phpUploadProjection(d phpDep, field string) bool {
	if d.container != "FILES" {
		return false
	}
	key := regexp.MustCompile(`\[\s*['"]` + regexp.QuoteMeta(field) + `['"]\s*\]\s*$`)
	for _, t := range d.dep.Transfers {
		if t.Kind == "field_projection" && (t.Text == field || key.MatchString(t.Text)) {
			return true
		}
	}
	return false
}

// uploadUse records a file_upload_candidate at move_uploaded_file(tmp, dest).
// The uploaded content is the claim's source; request-derived parts of the
// destination form the stored name. Type controls are read from the
// conditions that dominate the write.
func (f *phpFlow) uploadUse(n *sitter.Node, nodes []*sitter.Node, values []phpValue) {
	m := f.module
	content, dest := values[0], values[1]
	if len(content.deps) == 0 && len(dest.deps) == 0 {
		return
	}
	facts := &analysis.UploadFacts{Operation: "move_uploaded_file", ContractID: analysispacks.PHPMoveUploadedFile, Paths: []analysis.CommandPath{}}
	var deps []phpDep
	var operands []analysis.Evidence
	for i, slot := range []string{"upload_content", "stored_name"} {
		v := []phpValue{content, dest}[i]
		operands = append(operands, m.evidence("upload_operand", nodes[i]))
		for _, d := range v.deps {
			d.dep.SinkSlot = slot
			protection := "raw"
			if phpNonShellProtection(d.protection) == "unknown" || d.protection == phpUnwritten {
				protection = "unknown"
			}
			facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: len(deps), Operand: slot, Protection: protection})
			deps = append(deps, d)
		}
	}
	client, basename, partial, other := false, false, false, false
	for _, d := range dest.deps {
		switch {
		case phpUploadProjection(d, "name") && d.protection == "raw":
			client = true
		case phpUploadProjection(d, "name") && d.protection == "component":
			basename = true
		case phpUploadProjection(d, "name"):
			partial = true // a transform of the client name, such as its extension
		default:
			other = true
		}
	}
	prefix := phpPrefixOf(dest)
	switch {
	case client || other && !partial:
		facts.StoredName, facts.ExtensionOrigin = "client", "client"
	case basename && !partial:
		facts.StoredName, facts.ExtensionOrigin = "client_basename", "client"
	case partial:
		facts.StoredName, facts.ExtensionOrigin = "mixed", "client"
	case len(dest.deps) == 0:
		facts.StoredName, facts.ExtensionOrigin = "server_generated", "unknown"
		if phpConstantText(dest) && phpExtension.MatchString(phpPrefixOf(dest)) {
			facts.ExtensionOrigin = "fixed"
		}
	default:
		facts.StoredName, facts.ExtensionOrigin = "unknown", "unknown"
	}
	u := f.addUse("file_upload_candidate", n, phpValue{deps: deps, gaps: append(append([]analysis.Gap{}, content.gaps...), dest.gaps...)})
	base := len(u.Context)
	u.Context = append(u.Context, operands...)
	u.Context = append(u.Context, m.evidence("sink_binding", phpCallee(n)))
	// Type controls: each condition on the flow to this write.
	clientNames := f.uploadNameVars()
	typeVars := f.uploadTypeVars()
	for _, e := range f.context {
		if e.Kind != "branch_precondition" {
			continue
		}
		kinds := map[string]bool{}
		if strings.Contains(e.Text, "['type']") || strings.Contains(e.Text, `["type"]`) || mentionsVar(e.Text, typeVars) {
			kinds[analysis.UploadClientDeclaredType] = true
		}
		if phpContentSniff.MatchString(e.Text) {
			kinds[analysis.UploadContentSniff] = true
		}
		if phpReEncode.MatchString(e.Text) {
			kinds[analysis.UploadReEncode] = true
		}
		if mentionsVar(e.Text, clientNames) && phpLiteralTest.MatchString(e.Text) {
			kinds[analysis.UploadExtensionAllowList] = true
		}
		if len(kinds) == 0 {
			continue
		}
		index := len(u.Context)
		u.Context = append(u.Context, e)
		for _, kind := range []string{analysis.UploadClientDeclaredType, analysis.UploadExtensionAllowList, analysis.UploadContentSniff, analysis.UploadReEncode} {
			if kinds[kind] {
				facts.TypeControls = append(facts.TypeControls, analysis.UploadControl{Kind: kind, Context: index, ClientControlled: kind == analysis.UploadClientDeclaredType})
			}
		}
	}
	for _, c := range facts.TypeControls {
		if c.Kind == analysis.UploadExtensionAllowList && facts.ExtensionOrigin == "client" {
			facts.ExtensionOrigin = "allow_listed"
		}
	}
	facts.Destination, facts.DestinationServed = f.uploadDestination(prefix)
	u.Upload = facts
	u.APIModel = analysispacks.UploadContract(analysispacks.PHPMoveUploadedFile)
	roles := map[string][]analysis.Evidence{
		"sink_binding":     {m.evidence("sink_binding", phpCallee(n))},
		"invoked_callable": {f.entryEvidence()},
		"control_flow":     append([]analysis.Evidence{m.evidence("operation", n)}, f.context...),
		"upload_operand":   u.Context[base : base+len(operands)],
	}
	var blockers []analysis.Gap
	for _, g := range append(append([]analysis.Gap{}, content.gaps...), dest.gaps...) {
		switch g.Kind {
		case "php_parameter_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "php_global_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			blockers = append(blockers, g)
		}
	}
	u.Completeness = parse.UploadCompleteness(u, roles, blockers, u.Gaps)
}

// uploadDestination resolves the destination's literal directory against
// the entry file's directory (the PHP working directory). Plain PHP serves
// every file under the scan root, so a directory inside it is served.
func (f *phpFlow) uploadDestination(prefix string) (string, string) {
	if prefix == "" || !strings.Contains(prefix, "/") {
		return "", "unknown"
	}
	dir := prefix[:strings.LastIndex(prefix, "/")+1]
	if strings.HasPrefix(dir, "/") {
		return dir, "unknown"
	}
	entry := f.module.file
	if f.entryModule != nil {
		entry = f.entryModule.file
	}
	resolved := path.Clean(path.Join(path.Dir(entry), dir))
	if resolved == ".." || strings.HasPrefix(resolved, "../") {
		return resolved, "no"
	}
	return resolved, "yes"
}

// uploadNameVars and uploadTypeVars name the variables holding the client
// file name (or a transform of it) and the client-declared type.
func (f *phpFlow) uploadNameVars() []string { return f.uploadVars("name") }
func (f *phpFlow) uploadTypeVars() []string { return f.uploadVars("type") }

func (f *phpFlow) uploadVars(field string) []string {
	var out []string
	for name, v := range f.env {
		for _, d := range v.deps {
			if phpUploadProjection(d, field) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

func mentionsVar(text string, names []string) bool {
	for _, name := range names {
		if regexp.MustCompile(`\$` + regexp.QuoteMeta(name) + `\b`).MatchString(text) {
			return true
		}
	}
	return false
}
