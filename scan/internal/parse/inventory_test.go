package parse

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/walk"
)

func TestRunnersFollowEntryModes(t *testing.T) {
	inv, err := testInventory("../pipeline/testdata/mixed/three-language")
	if err != nil {
		t.Fatal(err)
	}
	pyOnly, err := testInventory("../langpy/testdata/routes")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		inv   Inventory
		entry string
		want  Languages
	}{
		{inv, NormalizeEntry("."), Languages{JavaScript: true, Python: true, PHP: true}},
		{pyOnly, "", Languages{JavaScript: true, Python: true}},
		{inv, NormalizeEntry("./app.py"), Languages{Python: true}},
		{inv, "index.php", Languages{PHP: true}},
		{inv, "view.PHTML", Languages{PHP: true}},
		{inv, "server.js", Languages{JavaScript: true}},
	} {
		if got := tc.inv.Runners(tc.entry); got != tc.want {
			t.Errorf("Runners(%q) = %+v, want %+v", tc.entry, got, tc.want)
		}
	}
}

func testInventory(root string) (Inventory, error) {
	files, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{Root: root, Files: files.Files}, nil
}
