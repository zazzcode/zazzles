package langjs

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

var consoleMethods = map[string]bool{"log": true, "info": true, "warn": true, "error": true, "debug": true, "trace": true}
var winstonMethods = map[string]bool{"log": true, "info": true, "warn": true, "error": true, "debug": true, "verbose": true, "silly": true, "http": true}

// logSink returns logger-binding evidence when the callee is a verified logging
// method. Names alone never qualify: console must be the unshadowed global and a
// winston logger must be created by winston's createLogger.
func (f *flow) logSink(call, fn *sitter.Node) (analysis.Evidence, bool) {
	if f.module == nil || fn == nil || fn.Kind() != "member_expression" {
		return analysis.Evidence{}, false
	}
	obj := fn.ChildByFieldName("object")
	prop := fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" {
		return analysis.Evidence{}, false
	}
	m := f.module
	name, method := obj.Utf8Text(m.src), prop.Utf8Text(m.src)
	if shadowed(call, name, m.src) {
		return analysis.Evidence{}, false
	}
	if name == "console" {
		if !consoleMethods[method] || moduleBinds(m, name) {
			return analysis.Evidence{}, false
		}
		return m.evidence("logger_binding", fn), true
	}
	if f.set == nil {
		return analysis.Evidence{}, false
	}
	if winstonMethods[method] {
		if e, ok := f.set.winstonLogger(m, name); ok {
			return e, true
		}
	}
	if pinoMethods[method] {
		return f.set.pinoLogger(m, name, 0)
	}
	return analysis.Evidence{}, false
}

var pinoMethods = map[string]bool{"trace": true, "debug": true, "info": true, "warn": true, "error": true, "fatal": true}

// pinoLogger verifies a binding created by pino(options?, destination?), or a
// child of one, here or through one named/default import. The binding evidence
// is the creating call, so options such as `redact` reach the model as source.
func (s *moduleSet) pinoLogger(m *sourceModule, name string, depth int) (analysis.Evidence, bool) {
	if depth > 2 {
		return analysis.Evidence{}, false
	}
	if imp, ok := m.imports[name]; ok && topVariable(m, name) == nil {
		target := s.importModule(m, imp.module)
		if target == nil {
			return analysis.Evidence{}, false
		}
		if imp.name == "default" {
			if v := defaultExport(target); v != nil && pinoCreate(target, v) {
				return target.evidence("logger_binding", v), true
			}
			return analysis.Evidence{}, false
		}
		if imp.name == "*" || !exportedName(target, imp.name) || bindingReassigned(target, imp.name) {
			return analysis.Evidence{}, false
		}
		return s.pinoLogger(target, imp.name, depth+1)
	}
	v := unwrapTS(topVariable(m, name))
	if v == nil || bindingReassigned(m, name) {
		return analysis.Evidence{}, false
	}
	if pinoCreate(m, v) {
		return m.evidence("logger_binding", v), true
	}
	// logger.child(bindings) inherits the parent's configuration.
	if v.Kind() == "call_expression" {
		if fn := v.ChildByFieldName("function"); fn != nil && fn.Kind() == "member_expression" {
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj != nil && prop != nil && obj.Kind() == "identifier" && prop.Utf8Text(m.src) == "child" {
				if parent, ok := s.pinoLogger(m, obj.Utf8Text(m.src), depth+1); ok {
					_ = parent
					return m.evidence("logger_binding", v), true
				}
			}
		}
	}
	return analysis.Evidence{}, false
}

func pinoCreate(m *sourceModule, n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil || n.Kind() != "call_expression" {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "identifier" {
		return false
	}
	imp, ok := m.imports[fn.Utf8Text(m.src)]
	return ok && imp.module == "pino" && (imp.name == "default" || imp.name == "pino")
}

// recordLogSink adds a logging use only when an argument carries a classified
// request dependency. Constant and unclassified messages produce no record.
func (f *flow) recordLogSink(n *sitter.Node, binding analysis.Evidence, values []value) {
	v := value{}
	for _, a := range values {
		v = combine(v, a)
	}
	claims := f.classifyLogDeps(v.deps, n)
	if len(claims) == 0 {
		return
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), v.gaps...)
	gaps = append(gaps, claims...)
	gaps = append(gaps, f.gap("log_destination_unresolved", "logger transports, levels, formats and redaction configuration are not modeled", n))
	context := append(append([]analysis.Evidence{}, f.context...), binding)
	f.uses = append(f.uses, analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, n.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID, Kind: "log_sink_candidate", Sink: f.module.evidence("log_sink_candidate", n), Dependencies: v.deps, Context: context, Gaps: gaps, Assessment: analysis.Assessment{Status: "not_run"}})
}

// moduleBinds reports a module-level import, function, or variable with this name.
func moduleBinds(m *sourceModule, name string) bool {
	if _, ok := m.imports[name]; ok {
		return true
	}
	return m.funcs[name] != nil || topVariable(m, name) != nil
}

// winstonLogger verifies a local or imported binding created by winston.
func (s *moduleSet) winstonLogger(m *sourceModule, name string) (analysis.Evidence, bool) {
	if imp, ok := m.imports[name]; ok {
		if imp.module == "winston" && (imp.name == "default" || imp.name == "*") {
			return m.evidence("logger_binding", imp.declaration), true
		}
		target := s.importModule(m, imp.module)
		if target == nil {
			return analysis.Evidence{}, false
		}
		var value *sitter.Node
		if imp.name == "default" {
			value = defaultExport(target)
		} else if exportedName(target, imp.name) {
			value = topVariable(target, imp.name)
		}
		if value != nil && winstonCreate(target, value) {
			return target.evidence("logger_binding", value), true
		}
		return analysis.Evidence{}, false
	}
	if value := topVariable(m, name); value != nil && winstonCreate(m, value) {
		return m.evidence("logger_binding", value), true
	}
	return analysis.Evidence{}, false
}

// defaultExport returns the value of `export default <expr>`, following one
// top-level identifier.
func defaultExport(m *sourceModule) *sitter.Node {
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "export_statement" {
			continue
		}
		v := n.ChildByFieldName("value")
		if v == nil {
			continue
		}
		if v.Kind() == "identifier" {
			return topVariable(m, v.Utf8Text(m.src))
		}
		return v
	}
	return nil
}

func winstonCreate(m *sourceModule, n *sitter.Node) bool {
	if n == nil || n.Kind() != "call_expression" {
		return false
	}
	fn := n.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	switch fn.Kind() {
	case "member_expression":
		obj := fn.ChildByFieldName("object")
		prop := fn.ChildByFieldName("property")
		if obj == nil || prop == nil || obj.Kind() != "identifier" || prop.Utf8Text(m.src) != "createLogger" {
			return false
		}
		imp, ok := m.imports[obj.Utf8Text(m.src)]
		return ok && imp.module == "winston" && (imp.name == "default" || imp.name == "*")
	case "identifier":
		imp, ok := m.imports[fn.Utf8Text(m.src)]
		return ok && imp.module == "winston" && imp.name == "createLogger"
	}
	return false
}
