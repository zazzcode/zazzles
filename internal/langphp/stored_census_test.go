package langphp

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/parse"
)

// TestStoredWriteCensus (AC3, W3a): an unresolved PHP SQL column read carries
// every write of its table with literal flags and keeps its Review blocker.
func TestStoredWriteCensus(t *testing.T) {
	r := phpAnalyze(t, phpFixture(t, map[string]string{
		"setup.php": "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\nmysqli_query($conn, \"CREATE TABLE users (id INT, first_name VARCHAR(15))\");\nmysqli_query($conn, \"INSERT INTO users (id, first_name) VALUES (1, 'admin')\");\n",
		"edit.php":  "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\n$name = $_POST['name'];\nmysqli_query($conn, \"UPDATE users SET last_name = '$name' WHERE id = 1\");\n",
		"index.php": "<?php\n$conn = mysqli_connect('h', 'u', 'p', 'd');\n$result = mysqli_query($conn, \"SELECT first_name FROM users\");\n$row = mysqli_fetch_assoc($result);\necho \"First: {$row['first_name']}\";\n",
	}), "")
	parse.CensusStoredWrites(r)
	parse.KeepStoredOriginFacts(r)
	for _, u := range phpUsesOfKind(r, "xss_candidate") {
		if u.StoredOrigin == nil {
			continue
		}
		set := u.StoredOrigin.Stores[0]
		if set.Key != "php-sql:users.first_name" || set.Schema == nil || len(set.Writes) != 2 {
			t.Fatalf("write set: %+v", set)
		}
		literal := map[string]bool{}
		for _, w := range set.Writes {
			literal[w.Evidence.Span.File] = w.Literal
		}
		if !literal["setup.php"] || literal["edit.php"] {
			t.Fatalf("literal flags: %+v", set.Writes)
		}
		if u.XSS.OriginResolved {
			t.Fatal("the census must not change the record's status")
		}
		return
	}
	t.Fatalf("no unresolved stored read with a write set: %+v", phpUsesOfKind(r, "xss_candidate"))
}
