package analysispacks

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSymfonyCatalog(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		component string
		contract  *analysis.APIModel
	}{
		{"api.php-doctrine-dbal-v1", SQLContract("php-doctrine-dbal-v1")},
		{"api.php-doctrine-orm-v1", SQLContract("php-doctrine-orm-v1")},
		{"render.twig-html-output-v1", XSSContract("twig-html-output-v1", "")},
		{"render.symfony-response-v1", XSSContract("symfony-response-v1", "")},
		{"api.symfony-process-v1", CommandContract("symfony-process-v1")},
		{"api.symfony-file-response-v1", PathContract("symfony-file-response-v1")},
		{"api.symfony-uploaded-file-move-v1", UploadContract("symfony-uploaded-file-move-v1")},
		{"api.php-url-open-v1", SSRFContract("php-url-open-v1")},
		{"api.symfony-http-client-v1", SSRFContract("symfony-http-client-v1")},
		{"api.symfony-redirect-v1", RedirectContract("symfony-redirect-v1")},
	} {
		t.Run(tc.component, func(t *testing.T) {
			if tc.contract == nil || tc.contract.Semantics == "" || !strings.HasPrefix(tc.contract.Reference, "https://") {
				t.Fatalf("missing operation contract, semantics or reference: %+v", tc.contract)
			}
			if component, ok := embedded.components[tc.component]; !ok || component.Material == "" {
				t.Fatalf("missing component material: %+v", component)
			}
		})
	}
	for _, id := range []string{"source.symfony-input-v1", "language.ssrf.php", "language.logging.php"} {
		t.Run(id, func(t *testing.T) {
			if component, ok := embedded.components[id]; !ok || !strings.Contains(component.Material, "https://") {
				t.Fatalf("missing material or reference: %+v", component)
			}
		})
	}
}
