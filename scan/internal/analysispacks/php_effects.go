package analysispacks

// PHPContentEffect is a builtin's conservative content-flow contract. It says
// nothing about validation or encoding suitability in a sink context.
type PHPContentEffect struct {
	Argument         int
	MutatesArgument  bool
	MinArgs, MaxArgs int
}

// PHPBuiltinContentEffect returns only the closed, reviewed builtin subset.
// Callers must exclude user-defined, namespaced and dynamic callees first.
func PHPBuiltinContentEffect(name string) (PHPContentEffect, bool) {
	switch name {
	case "array_shift":
		return PHPContentEffect{0, true, 1, 1}, true
	case "json_decode":
		return PHPContentEffect{0, false, 1, 4}, true
	case "base64_decode":
		return PHPContentEffect{0, false, 1, 2}, true
	case "base64_encode", "addslashes":
		return PHPContentEffect{0, false, 1, 1}, true
	case "strrpos":
		return PHPContentEffect{0, false, 2, 3}, true
	}
	return PHPContentEffect{}, false
}
