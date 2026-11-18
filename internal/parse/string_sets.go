package parse

// appendUniqueString appends s to a unless a already holds it.
func appendUniqueString(a []string, s string) []string {
	for _, v := range a {
		if v == s {
			return a
		}
	}
	return append(a, s)
}
