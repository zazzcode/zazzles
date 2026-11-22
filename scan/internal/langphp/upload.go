package langphp

import (
	"path"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
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

const symfonyUploadOperation = "UploadedFile::move"

func (f *phpFlow) symfonyUploadMove(n *sitter.Node, receiver phpValue, method string, nodes []*sitter.Node, values []phpValue) bool {
	if f.symfony == nil || !strings.EqualFold(receiver.class, symfonyUploadedFileClass) ||
		!strings.EqualFold(method, "move") || len(values) == 0 || len(values) > 2 {
		return false
	}
	dir := values[0]
	var name phpValue
	if len(values) == 2 {
		name = values[1]
	}

	// The library uses the final name component but honors the directory
	// operand as supplied. This is independent of the upload type claim.
	pathArgs := []phpValue{dir, phpProtect(name, "component")}
	f.pathUse(n, symfonyUploadOperation, nodes, pathArgs, analysispacks.SymfonyUploadedFileMove, "write")
	if len(receiver.deps)+len(dir.deps)+len(name.deps) == 0 {
		return true
	}

	facts := f.symfonyUploadFacts(dir, name)
	binding := f.module.evidence("sink_binding", phpCallee(n))
	operands := []analysis.Evidence{f.module.evidence("upload_operand", phpField(n, "object"))}
	for _, node := range nodes {
		operands = append(operands, f.module.evidence("upload_operand", node))
	}
	var written phpValue
	for _, operand := range []struct {
		value phpValue
		slot  string
	}{{receiver, "upload_content"}, {dir, "stored_name"}, {name, "stored_name"}} {
		written.deps = append(written.deps, phpSlot(operand.value, operand.slot).deps...)
		written.gaps = append(written.gaps, operand.value.gaps...)
	}
	u := f.addUse("file_upload_candidate", n, written)
	u.Upload, u.APIModel = facts, analysispacks.UploadContract(facts.ContractID)
	f.symfonyUploadControls(u, receiver, name)
	for i, d := range written.deps {
		protection := "raw"
		if phpNonShellProtection(d.protection) == "unknown" || d.protection == phpUnwritten {
			protection = "unknown"
		}
		facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: i, Operand: d.dep.SinkSlot, Protection: protection})
	}
	u.Context = append(u.Context, binding)
	u.Context = append(u.Context, operands...)
	roles := map[string][]analysis.Evidence{
		"sink_binding":     {binding},
		"invoked_callable": {f.entryEvidence()},
		"control_flow":     append([]analysis.Evidence{f.module.evidence("operation", n)}, f.context...),
		"upload_operand":   operands,
	}
	var blockers []analysis.Gap
	for _, gap := range written.gaps {
		switch gap.Kind {
		case "php_parameter_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "php_global_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			blockers = append(blockers, gap)
		}
	}
	u.Completeness = parse.UploadCompleteness(u, roles, blockers, u.Gaps)
	return true
}

func (f *phpFlow) symfonyUploadFacts(dir, name phpValue) *analysis.UploadFacts {
	facts := &analysis.UploadFacts{Operation: symfonyUploadOperation, ContractID: analysispacks.SymfonyUploadedFileMove,
		StoredName: "unknown", ExtensionOrigin: "unknown", DestinationServed: "unknown"}
	if directory, ok := phpSQLText(dir); ok && path.IsAbs(directory) {
		facts.Destination, facts.DestinationServed = path.Clean(directory), "no"
		if f.symfony.servedPath(directory) {
			facts.DestinationServed = "yes"
		}
	}
	if len(name.deps) == 0 {
		facts.StoredName = "server_generated"
	}
	for _, d := range name.deps {
		switch f.phpUploadMetadata(d) {
		case "getclientoriginalname":
			facts.ExtensionOrigin = "client"
			if len(name.deps) == 1 && !name.built && d.protection == "raw" {
				facts.StoredName = "client"
			}
		case "getclientoriginalextension", "client_extension":
			facts.ExtensionOrigin = "client"
		case "guessextension":
			if facts.ExtensionOrigin != "client" {
				facts.ExtensionOrigin = "content_derived"
			}
		}
	}
	if facts.ExtensionOrigin == "client" && name.built {
		facts.StoredName = "mixed"
	}
	if phpConstantText(name) && phpExtension.MatchString(phpPrefixOf(name)) {
		facts.ExtensionOrigin = "fixed"
	}
	return facts
}

func (f *phpFlow) phpUploadMetadata(d phpDep) string {
	if !strings.EqualFold(d.container, "files") {
		return ""
	}
	for _, e := range d.dep.Transfers {
		if e.Kind == "upload_extension_projection" {
			return "client_extension"
		}
	}
	m := f.set.modules[d.dep.Source.Span.File]
	if m == nil {
		return ""
	}
	span := d.dep.Source.Span
	source := parse.NodeAt(m.tree.RootNode(), span.StartByte, span.EndByte)
	if source == nil || source.Kind() != "member_call_expression" {
		return ""
	}
	return strings.ToLower(phpText(m, phpCallee(source)))
}

// symfonyUploadNameCall preserves the client-name provenance of the extension
// selected by the PHP pathinfo overload.
func (f *phpFlow) symfonyUploadNameCall(n *sitter.Node, name string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	if f.symfony == nil || !strings.EqualFold(name, "pathinfo") || len(values) != 2 ||
		strings.TrimPrefix(phpText(f.module, nodes[1]), `\`) != "PATHINFO_EXTENSION" ||
		!f.set.phpDeserializationBuiltin(f.module, phpCallee(n)) {
		return phpValue{}, false
	}
	for _, d := range values[0].deps {
		if f.phpUploadMetadata(d) == "getclientoriginalname" {
			return phpTransfer(values[0], f.module.evidence("upload_extension_projection", n)), true
		}
	}
	return phpValue{}, false
}

func (f *phpFlow) symfonyUploadControls(u *analysis.CandidateUse, receiver, name phpValue) {
	for i, e := range u.Context {
		if e.Span.File != f.module.file || e.Kind != "branch_precondition" && e.Kind != "branch_false_precondition" {
			continue
		}
		test := parse.NodeAt(f.module.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
		if test == nil {
			continue
		}
		kinds := map[string]bool{}
		f.symfonyUploadTypeTest(test, e.Kind == "branch_precondition", receiver, name, kinds)
		for _, kind := range []string{analysis.UploadClientDeclaredType, analysis.UploadContentSniff, analysis.UploadExtensionAllowList} {
			if !kinds[kind] {
				continue
			}
			u.Upload.TypeControls = append(u.Upload.TypeControls, analysis.UploadControl{
				Kind: kind, Context: i, ClientControlled: kind == analysis.UploadClientDeclaredType,
			})
			if kind == analysis.UploadExtensionAllowList {
				u.Upload.ExtensionOrigin = "allow_listed"
			}
		}
	}
}

func (f *phpFlow) symfonyUploadTypeTest(test *sitter.Node, truth bool, receiver, name phpValue, kinds map[string]bool) {
	if test == nil {
		return
	}
	m := f.module
	switch test.Kind() {
	case "parenthesized_expression":
		if inner := firstNamedChild(test); inner != nil {
			f.symfonyUploadTypeTest(inner, truth, receiver, name, kinds)
		}
		return
	case "unary_op_expression":
		if inner := phpField(test, "argument"); inner != nil && strings.HasPrefix(phpText(m, test), "!") {
			f.symfonyUploadTypeTest(inner, !truth, receiver, name, kinds)
			return
		}
	case "binary_expression":
		switch strings.ToLower(phpOperator(m, test)) {
		case "&&", "and":
			if !truth {
				return
			}
			f.symfonyUploadTypeTest(phpField(test, "left"), truth, receiver, name, kinds)
			f.symfonyUploadTypeTest(phpField(test, "right"), truth, receiver, name, kinds)
			return
		case "||", "or":
			if truth {
				return
			}
			f.symfonyUploadTypeTest(phpField(test, "left"), truth, receiver, name, kinds)
			f.symfonyUploadTypeTest(phpField(test, "right"), truth, receiver, name, kinds)
			return
		}
	}
	if test.Kind() == "function_call_expression" {
		callee := phpCallee(test)
		args := phpArgs(test)
		if strings.EqualFold(strings.TrimPrefix(phpText(m, callee), `\`), "in_array") && len(args) >= 2 &&
			f.set.phpDeserializationBuiltin(m, callee) && len(phpArrayLiteralStrings(m, args[1])) > 0 {
			if f.symfonyUploadFinalExtension(args[0], name, test.StartByte()) {
				if truth {
					kinds[analysis.UploadExtensionAllowList] = true
				}
				return
			}
		}
	}
	phpWalk(test, func(node *sitter.Node) {
		switch f.symfonyUploadControlMethod(node, receiver, name, test.StartByte()) {
		case "getclientmimetype":
			kinds[analysis.UploadClientDeclaredType] = true
		case "getmimetype", "guessextension":
			kinds[analysis.UploadContentSniff] = true
		}
	})
}

func (f *phpFlow) symfonyUploadFinalExtension(n *sitter.Node, name phpValue, at uint) bool {
	v := f.env[phpVarName(f.module, n)]
	if !f.symfonyUploadBefore(v, at) || len(v.deps) == 0 || v.built {
		return false
	}
	for _, d := range v.deps {
		switch f.phpUploadMetadata(d) {
		case "getclientoriginalextension", "client_extension", "guessextension":
		default:
			return false
		}
		found := false
		for _, operand := range name.deps {
			found = found || operand.dep.Source == d.dep.Source
		}
		if !found {
			return false
		}
	}
	return true
}

func (f *phpFlow) symfonyUploadControlMethod(n *sitter.Node, receiver, name phpValue, at uint) string {
	if n.Kind() == "member_call_expression" {
		obj := f.env[phpVarName(f.module, phpField(n, "object"))]
		if !f.symfonyUploadBefore(obj, at) || !strings.EqualFold(obj.class, symfonyUploadedFileClass) {
			return ""
		}
		for _, current := range receiver.deps {
			for _, checked := range obj.deps {
				if current.dep.Source == checked.dep.Source {
					return strings.ToLower(phpText(f.module, phpCallee(n)))
				}
			}
		}
		return ""
	}
	v := f.env[phpVarName(f.module, n)]
	if !f.symfonyUploadBefore(v, at) {
		return ""
	}
	for _, checked := range v.deps {
		for _, from := range append(append([]phpDep{}, receiver.deps...), name.deps...) {
			if checked.key == from.key && strings.EqualFold(from.container, "files") {
				switch method := f.phpUploadMetadata(checked); method {
				case "getclientmimetype", "getmimetype", "guessextension":
					return method
				}
			}
		}
	}
	return ""
}

// A reassigned variable may no longer denote the value inspected by a guard.
func (f *phpFlow) symfonyUploadBefore(v phpValue, at uint) bool {
	for _, d := range v.deps {
		if s := d.dep.Source.Span; s.File == f.module.file && s.StartByte >= int(at) {
			return false
		}
		for _, e := range d.dep.Transfers {
			if e.Kind == "assignment" && e.Span.File == f.module.file && e.Span.StartByte >= int(at) {
				return false
			}
		}
	}
	return true
}
