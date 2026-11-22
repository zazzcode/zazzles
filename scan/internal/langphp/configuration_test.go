package langphp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/deployconf"
)

func TestScheduleSmoke(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"composer.json":    `{"require":{"symfony/framework-bundle":"^6.4"},"autoload":{"psr-4":{"App\\":"src/"}}}`,
		"public/index.php": "<?php\n",
		"bin/job.php":      "<?php\n",
		"bin/tick.sh":      "#!/bin/sh\nphp bin/job.php\n",
		"Dockerfile":       "FROM scratch\nWORKDIR /srv\nCOPY ./ /srv\nRUN chown web:web /srv/bin/job.php\nRUN echo \"* * * * * root cd /srv && sh bin/tick.sh\" > /etc/cron.d/site\n",
	})
	raw, _ := os.ReadFile(filepath.Join(root, "Dockerfile"))
	img := deployconf.Dockerfile("Dockerfile", raw)
	t.Logf("map %v schedules %+v owners %+v gaps %+v", img.PathMap, img.Schedules, img.Owners, img.Gaps)
	r := phpAnalyze(t, root, "")
	n := 0
	for _, u := range r.Uses {
		if u.Kind == analysis.ConfigurationKind && u.Configuration != nil && u.Configuration.Check == analysis.CheckScheduledPrivileged {
			n++
			t.Logf("%s joined %d", u.Configuration.Value, len(u.Configuration.Joined))
			for _, j := range u.Configuration.Joined {
				t.Logf("  %s %s %s:%d", j.Kind, j.Text, j.Span.File, j.Span.StartLine)
			}
		}
	}
	if n != 1 {
		t.Fatalf("schedule candidates %d", n)
	}
}

func TestSymfonyConfigurationSmoke(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"composer.json": `{
			"require": {"symfony/framework-bundle": "^6.4", "doctrine/orm": "^2.19"},
			"autoload": {"psr-4": {"App\\": "src/"}}
		}`,
		"public/index.php":                  "<?php\n",
		"config/packages/security.yaml":     "security:\n  access_control:\n    - { path: ^/locked, roles: ROLE_USER }\n",
		"config/packages/framework.yaml":    "framework:\n  csrf_protection: false\n  session:\n    cookie_httponly: false\n    cookie_secure: false\n",
		"config/packages/web_profiler.yaml": "web_profiler:\n  toolbar: true\n",
		"src/Entity/Note.php":               "<?php\nnamespace App\\Entity;\nuse Doctrine\\ORM\\Mapping as ORM;\n#[ORM\\Entity]\nclass Note {\n  #[ORM\\Column]\n  private ?string $body = null;\n  public function setBody(string $body): void { $this->body = $body; }\n}\n",
		"src/Controller/NoteController.php": "<?php\nnamespace App\\Controller;\nuse App\\Entity\\Note;\nuse Symfony\\Component\\HttpFoundation\\Request;\nuse Symfony\\Component\\HttpFoundation\\Response;\nuse Symfony\\Component\\Routing\\Attribute\\Route;\nclass NoteController {\n  #[Route('/locked/{note}/write', methods: ['POST'])]\n  public function write(Note $note, Request $request): Response {\n    $note->setBody($request->request->get('body'));\n    return new Response('');\n  }\n  #[Route('/locked/{note}/other', methods: ['POST'])]\n  public function other(Note $note, Request $request): Response {\n    if (!$this->isCsrfTokenValid('note', $request->request->get('token'))) { return new Response('', 403); }\n    $note->setBody($request->request->get('body'));\n    return new Response('');\n  }\n  #[Route('/open/{note}/write', methods: ['POST'])]\n  public function open(Note $note, Request $request): Response {\n    $note->setBody($request->request->get('body'));\n    return new Response('');\n  }\n}\n",
	})
	r := phpAnalyze(t, root, "")
	var lines []string
	for _, u := range r.Uses {
		if u.Kind != analysis.ConfigurationKind || u.Configuration == nil {
			continue
		}
		lines = append(lines, u.Configuration.Check+" "+u.Sink.Span.File+":"+itoa(u.Sink.Span.StartLine)+" joined="+itoa(len(u.Configuration.Joined))+" mit="+itoa(len(u.Configuration.Mitigations)))
	}
	t.Logf("entries %d\n%s", len(r.Entries), strings.Join(lines, "\n"))
	for _, e := range r.Entries {
		auth := ""
		if e.Access != nil {
			auth = e.Access.Authentication
		}
		t.Logf("entry %s access %s changes %d", e.Name, auth, len(e.StateChanges))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
