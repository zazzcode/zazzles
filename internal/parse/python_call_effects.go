package parse

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// pyContainerWrites maps a list method to the argument whose value it stores.
var pyContainerWrites = map[string]int{"append": 0, "extend": 0, "insert": 1}

// containerWrite applies the container_write effect: a local, module-stable list
// receiver gains the stored argument's dependencies, and the call returns None.
func (f *pythonFlow) containerWrite(call, object *sitter.Node, method string, receiver pythonValue, values []pythonValue) (pythonValue, bool) {
	arg, ok := pyContainerWrites[method]
	if !ok || object == nil || object.Kind() != "identifier" || len(values) != arg+1 {
		return pythonValue{}, false
	}
	name := pyText(f.module, object)
	if _, local := f.env[name]; !local || !f.module.bindingIndex().list(name) {
		return pythonValue{}, false
	}
	f.env[name] = pyCombine(receiver, values[arg])
	return pythonValue{}, true
}
