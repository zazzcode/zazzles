package guidelines

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestFactNotes(t *testing.T) {
	notes, err := FactNotes([]string{"Operand path facts: x", "output_context=html_text", "native_hash_hex: crypto.createHash('md5').update(x).digest('hex') at a.js", "scope_express_direct", "native_hash_hex: other at b.js"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(notes, "- `native_hash_hex`") != 1 || !strings.Contains(notes, "- `scope_express_direct`") || strings.Contains(notes, "scope_grpc_unary") {
		t.Fatalf("notes:\n%s", notes)
	}
	// Document order, not request order.
	if strings.Index(notes, "scope_express_direct") > strings.Index(notes, "native_hash_hex") {
		t.Fatalf("notes not in document order:\n%s", notes)
	}
	if notes, err := FactNotes([]string{"Operand path facts: x", "protection=raw"}); err != nil || notes != "" {
		t.Fatalf("uncoded facts produced notes %q %v", notes, err)
	}
	if _, err := FactNotes([]string{"undeclared_code: x"}); err == nil {
		t.Fatal("an unknown fact code reached the model without its note")
	}
}

func TestFactCodesAreDocumented(t *testing.T) {
	for _, code := range []string{"scope_express_direct", "scope_node_framework", "scope_apollo_resolver", "scope_grpc_unary", "nosql_selector_semantics", "conditional_value_paths", "validator_is_email", "express_transport_adapters", "verified_number_call", "native_hash_hex", "supported_transfer", "output_alternative_numeric", "output_alternative_unconstrained", "numeric_output_expression", "scope_nextjs", "zod_schema_supplied", "sql_multi_statement", "sql_single_statement", "script_reexecution", "browser_navigation_sink", "xss_via_fetched_content", "url_scheme_only_test", "vm_not_security_boundary", "code_inside_string_literal", "sandbox_library_advisory", "protocol_relative_path", "redirect_back_referer", "redirect_also_xss", "redirect_predicate_bypass", "redirect_predicate_excludes", "redirect_normalization", "sql_literal_quote_doubling", "escaped_in_quoted_literal", "hash_hex_result"} {
		if !KnownFact(code) {
			t.Fatalf("%s has no note", code)
		}
	}
	if len(factOrder) != 34 {
		t.Fatalf("fact codes %v: update the producer list in this test", factOrder)
	}
}

// TestProducedFactCodesHaveNotes scans the producers: every coded fact literal
// appended to ModelFacts in the parse package and the PHP SQL files must have a note, so a new code
// fails offline instead of failing a paid request at send time.
func TestProducedFactCodesHaveNotes(t *testing.T) {
	files, err := filepath.Glob("../parse/*.go")
	php, phpErr := filepath.Glob("../langphp/sql*.go")
	if err != nil || phpErr != nil || len(files) == 0 || len(php) == 0 {
		t.Fatalf("no producer sources: %v %v", err, phpErr)
	}
	files = append(files, php...)
	// Direct appends, and coded "snake_code: detail" literals built before appending.
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`ModelFacts[^\n]*?"([a-z][a-z0-9_]*)(?::|")`),
		regexp.MustCompile(`"([a-z][a-z0-9]*_[a-z0-9_]+): `),
	}
	found := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, code := range patterns {
			for _, m := range code.FindAllStringSubmatch(string(src), -1) {
				found++
				if !KnownFact(m[1]) {
					t.Errorf("%s produces fact code %q with no note in facts.md", filepath.Base(file), m[1])
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("no coded facts found; the producer pattern is stale")
	}
}
