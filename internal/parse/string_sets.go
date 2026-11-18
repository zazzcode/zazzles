package parse

// AppendUniqueString appends s to a unless a already holds it.
func AppendUniqueString(a []string, s string) []string {
	for _, v := range a {
		if v == s {
			return a
		}
	}
	return append(a, s)
}

// Itoa formats a non-negative int in decimal.
func Itoa(i int) string {
	const digits = "0123456789"
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{digits[i%10]}, b...)
	}
	return string(b)
}
