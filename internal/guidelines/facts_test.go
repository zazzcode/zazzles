package guidelines

import (
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
	for _, code := range []string{"scope_express_direct", "scope_node_framework", "scope_apollo_resolver", "scope_grpc_unary", "nosql_selector_semantics", "conditional_value_paths", "validator_is_email", "express_transport_adapters", "verified_number_call", "native_hash_hex", "supported_transfer", "output_alternative_numeric", "output_alternative_unconstrained", "numeric_output_expression", "scope_nextjs", "zod_schema_supplied", "sql_multi_statement", "sql_single_statement", "script_reexecution"} {
		if !KnownFact(code) {
			t.Fatalf("%s has no note", code)
		}
	}
	if len(factOrder) != 19 {
		t.Fatalf("fact codes %v: update the producer list in this test", factOrder)
	}
}
