package langphp

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestShellURLSmoke(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"public/index.php": "<?php\n$url = $_GET['u'];\nshell_exec('curl -s ' . $url);\nshell_exec('curl -s -o ' . $url . ' https://example.org/a');\nshell_exec('convert ' . $url . ' out.png');\nexec(\"wget -q $url\");\n$command = 'curl -k -s -o /dev/null -w \"%{http_code}\" ' . $url;\nshell_exec($command);\n",
	})
	r := phpAnalyze(t, root, "")
	var ssrf, cmd int
	for _, u := range r.Uses {
		switch u.Kind {
		case "ssrf_candidate":
			ssrf++
			tr := ""
			if u.Outbound != nil {
				tr = u.Outbound.Transport + " " + u.Outbound.Operation + " op=" + u.Outbound.Operand
			}
			t.Logf("ssrf %s:%d %s", u.Sink.Span.File, u.Sink.Span.StartLine, tr)
		case "command_execution_candidate":
			cmd++
		}
	}
	t.Logf("ssrf %d command %d", ssrf, cmd)
	if ssrf < 3 {
		t.Fatal("expected curl and wget shell URL candidates")
	}
	_ = analysis.ConfigurationKind
}
