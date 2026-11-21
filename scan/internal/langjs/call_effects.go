package langjs

import sitter "github.com/tree-sitter/go-tree-sitter"

// Call effects (step 1D): a closed table keyed by (receiver type, method) from
// the call index. An effect is a flow fact, never protection: nothing here marks
// a value safe or validated (spec D-9). A method missing from the table stays
// unknown and keeps its gap.

// jsIndependentResults lists calls whose result carries none of the receiver's
// or arguments' dependencies and no request source. Flow consults it only where
// a call already has no dependencies and would otherwise record
// unknown_call_result. Methods that return stored or external data (finders,
// JSON.parse, file reads) are deliberately absent.
var jsIndependentResults = map[string]map[string]bool{
	"module:os":             set("hostname", "type", "release", "platform", "arch", "cpus", "totalmem", "freemem", "uptime", "homedir", "tmpdir", "endianness", "loadavg", "networkInterfaces", "userInfo"),
	"module:config":         set("get", "has"),
	"builtin:JSON":          set("stringify"),
	"builtin:Math":          set("abs", "ceil", "floor", "round", "trunc", "max", "min", "pow", "random", "sqrt", "sign", "log", "exp"),
	"builtin:Date":          set("now", "UTC"),
	"builtin:Date#instance": set("toISOString", "toString", "toJSON", "toDateString", "toTimeString", "toLocaleString", "toLocaleDateString", "toLocaleTimeString", "toUTCString", "getTime", "valueOf", "getFullYear", "getMonth", "getDate", "getDay", "getHours", "getMinutes", "getSeconds", "getMilliseconds"),
	"sequelize_model":       set("count"),
}

func set(items ...string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, item := range items {
		out[item] = true
	}
	return out
}

// independentCall reports whether the indexed call has an independent result.
func (f *flow) independentCall(call *sitter.Node) bool {
	if f.set == nil || call.Kind() != "call_expression" {
		return false
	}
	r := f.set.callResolution(f.module, call)
	switch r.Kind {
	case callKnownClass, callBuiltinMethod, callPackageMember:
		return jsIndependentResults[r.Receiver][r.Method]
	}
	return false
}
