package langpy

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

// Python upload facts (close-findings-gaps W5): Werkzeug FileStorage.save on
// a request.files value.
var (
	pyClientType    = regexp.MustCompile(`\.(mimetype|content_type|mimetype_params)\b`)
	pyContentSniff  = regexp.MustCompile(`\b(imghdr\.what|magic\.from_\w+|filetype\.guess\w*|Image\.open|puremagic\.\w+)\s*\(`)
	pyExtensionTest = regexp.MustCompile(`\bin\b|\.endswith\s*\(|\ballowed_file\s*\(`)
)

// uploadCall records a file_upload_candidate at FileStorage.save(dst).
func (f *pythonFlow) uploadCall(n, fn, object *sitter.Node, receiver pythonValue, method string, nodes []*sitter.Node, values []pythonValue) {
	if method != "save" || object == nil || fn.Kind() != "attribute" || !uploadReceiver(receiver) || len(nodes) == 0 || len(values) == 0 {
		return
	}
	m := f.module
	dest := values[0]
	facts := &analysis.UploadFacts{Operation: "werkzeug.FileStorage.save", ContractID: analysispacks.PythonWerkzeugSave, DestinationServed: "unknown", Paths: []analysis.CommandPath{}}
	var all pythonValue
	for i, v := range []pythonValue{receiver, dest} {
		slot := []string{"upload_content", "stored_name"}[i]
		for _, d := range v.deps {
			d.dep.SinkSlot = slot
			protection := "raw"
			if d.protection == "unknown" {
				protection = "unknown"
			}
			facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: len(all.deps), Operand: slot, Protection: protection})
			all.deps = append(all.deps, d)
		}
	}
	all.gaps = append(append([]analysis.Gap{}, receiver.gaps...), dest.gaps...)
	client, sanitized := false, false
	for _, d := range dest.deps {
		if len(f.verifiedSanitizers(d.dep)) > 0 {
			sanitized = true
		} else {
			client = true
		}
	}
	switch {
	case client:
		facts.StoredName, facts.ExtensionOrigin = "client", "client"
	case sanitized:
		facts.StoredName, facts.ExtensionOrigin = "client_basename", "client"
	default:
		facts.StoredName, facts.ExtensionOrigin = "server_generated", "unknown"
	}
	u := f.addUse("file_upload_candidate", n, all)
	base := len(u.Context)
	u.Context = append(u.Context, m.evidence("upload_operand", object), m.evidence("upload_operand", nodes[0]), m.evidence("sink_binding", fn))
	for _, e := range f.context {
		if e.Kind != "branch_precondition" {
			continue
		}
		var kind string
		switch {
		case pyClientType.MatchString(e.Text):
			kind = analysis.UploadClientDeclaredType
		case pyContentSniff.MatchString(e.Text):
			kind = analysis.UploadContentSniff
		case strings.Contains(e.Text, "filename") && pyExtensionTest.MatchString(e.Text):
			kind = analysis.UploadExtensionAllowList
		default:
			continue
		}
		facts.TypeControls = append(facts.TypeControls, analysis.UploadControl{Kind: kind, Context: len(u.Context), ClientControlled: kind == analysis.UploadClientDeclaredType})
		u.Context = append(u.Context, e)
		if kind == analysis.UploadExtensionAllowList && facts.ExtensionOrigin == "client" {
			facts.ExtensionOrigin = "allow_listed"
		}
	}
	u.Upload = facts
	u.APIModel = analysispacks.UploadContract(analysispacks.PythonWerkzeugSave)
	var blockers []analysis.Gap
	for _, g := range all.gaps {
		if pythonCommandBlockers[g.Kind] && touchesCommandDependency(g, u.Dependencies) {
			blockers = append(blockers, g)
		}
	}
	u.Completeness = parse.UploadCompleteness(u, map[string][]analysis.Evidence{
		"sink_binding":     {m.evidence("sink_binding", fn)},
		"invoked_callable": {f.route.module.evidence("invoked_callable", f.route.fn)},
		"control_flow":     append([]analysis.Evidence{m.evidence("operation", n)}, f.context...),
		"upload_operand":   u.Context[base : base+2],
	}, blockers, u.Gaps)
}
