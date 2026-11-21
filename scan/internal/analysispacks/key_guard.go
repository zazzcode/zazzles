package analysispacks

import "slices"

var prototypeNames = []string{"__proto__", "constructor", "prototype"}

// ListPrototypeKeys partitions the names in stable order. A key can be blocked by
// an enforcing guard or by the verified library version.
func ListPrototypeKeys(blocked []string) (denied, open []string) {
	for _, key := range prototypeNames {
		if slices.Contains(blocked, key) {
			denied = append(denied, key)
		} else {
			open = append(open, key)
		}
	}
	return denied, open
}

// OpenPrototypeRoutes returns the leading names of the remaining inherited routes.
// A two-level assignment has one lookup followed by the final write.
func OpenPrototypeRoutes(open []string, levels int) []string {
	var routes []string
	if slices.Contains(open, "__proto__") {
		routes = append(routes, "__proto__")
	}
	if levels != 2 && slices.Contains(open, "constructor") && slices.Contains(open, "prototype") {
		routes = append(routes, "constructor")
	}
	return routes
}
