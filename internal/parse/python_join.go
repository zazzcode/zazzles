package parse

// pyJoin combines alternative values, including their field projections. Ordinary
// expression aggregation must not discard a raw field behind an escaped sibling.
func pyJoin(a, b pythonValue, depth int) pythonValue {
	if pyEmpty(a) {
		return b
	}
	if pyEmpty(b) {
		return a
	}
	result := pyCombine(a, b)
	result.finite = joinPythonFinite(a.finite, b.finite)
	if a.binding != b.binding || a.driver != b.driver {
		result.binding, result.driver = "", ""
		result.unknown = true
	}
	if a.templateEscape != b.templateEscape {
		result.templateEscape = "unknown"
	}
	if a.table != b.table {
		result.table = ""
	}
	if a.fields == nil && b.fields == nil {
		return result
	}
	if depth >= 8 {
		result.unknown = true
		return result
	}
	result.fields = map[string]pythonValue{}
	for key, value := range a.fields {
		other, ok := b.fields[key]
		if !ok {
			other = pythonValue{unknown: true}
		}
		result.fields[key] = pyJoin(value, other, depth+1)
	}
	for key, value := range b.fields {
		if _, exists := a.fields[key]; !exists {
			result.fields[key] = pyJoin(pythonValue{unknown: true}, value, depth+1)
		}
	}
	return result
}
