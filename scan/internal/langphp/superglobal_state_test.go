package langphp

import "testing"

func TestPHPSuperglobalWritesAcrossHelperReturns(t *testing.T) {
	for _, tc := range []struct {
		name, body, source string
	}{
		{"untouched early return", "if (isset($_POST['flag'])) { return; } $_GET['x'] = 'fixed';", "$_GET['x']"},
		{"write before early return", "if (isset($_POST['flag'])) { $_GET['x'] = $_POST['value']; return; } $_GET['x'] = 'fixed';", "$_POST['value']"},
		{"all returns write literals", "if (isset($_POST['flag'])) { $_GET['x'] = 'first'; return; } $_GET['x'] = 'second'; return;", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "<?php function change() {" + tc.body + "} change(); echo $_GET['x'];"
			checkSuperglobalSource(t, src, tc.source)
		})
	}
}

func TestPHPSuperglobalOverlappingWrites(t *testing.T) {
	for _, tc := range []struct {
		name, write, source string
	}{
		{"dynamic key", "$_GET[$_POST['key']] = $_POST['value'];", "$_POST['value']"},
		{"whole container", "$_GET = $_POST;", "$_POST"},
		{"distinct literal", "$_GET['y'] = $_POST['value'];", ""},
		{"distinct constant key", "$k = 'y'; $_GET[$k] = $_POST['value'];", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := "<?php $_GET['x'] = 'fixed'; " + tc.write + "echo $_GET['x'];"
			checkSuperglobalSource(t, src, tc.source)
		})
	}
}

func checkSuperglobalSource(t *testing.T, src, source string) {
	t.Helper()
	r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": src}), "index.php")
	uses := phpUsesOfKind(r, "xss_candidate")
	if source == "" {
		if len(uses) != 0 {
			t.Fatalf("rendering fixed values produced %d candidates", len(uses))
		}
		return
	}
	for _, u := range uses {
		for _, p := range u.XSS.Paths {
			if u.Dependencies[p.Dependency].Source.Text == source && p.Protection == "raw" {
				return
			}
		}
	}
	t.Fatalf("no raw path from %s to the output (%d candidates)", source, len(uses))
}
