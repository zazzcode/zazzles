package parse

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// InlineScript is literal inline JavaScript found in one text source. Masked has the length of the
// source snapshot with every byte outside the scripts blanked (line breaks kept), so offsets,
// lines and the snapshot hash stay those of the original file.
type InlineScript struct {
	File    string
	Masked  []byte
	Globals map[string]analysis.Evidence
}

// AnalyzeInlineScripts runs the browser adapter over inline scripts whose files texts holds and
// appends the records to out.
func AnalyzeInlineScripts(texts *TextSources, scripts []InlineScript, out *analysis.AnalysisReport) error {
	parsers, err := newParsers()
	if err != nil {
		return err
	}
	set := &moduleSet{root: texts.Root(), parsers: parsers, modules: map[string]*sourceModule{}, allowed: map[string]bool{}, text: texts}
	defer set.close()
	for _, script := range scripts {
		snapshot, _ := texts.Get(script.File)
		tree := parsers.js.Parse(script.Masked, nil)
		if tree == nil {
			return fmt.Errorf("no inline JavaScript tree for %s", script.File)
		}
		set.modules[script.File] = &sourceModule{file: script.File, src: []byte(snapshot.Text), hash: snapshot.SHA256, tree: tree, funcs: map[string]*sitter.Node{}, exports: map[string]*sitter.Node{}, imports: map[string]importBinding{}, express: map[string]bool{}, receivers: map[string]bool{}, browserGlobals: script.Globals}
		set.allowed[script.File] = true
	}
	return set.browser(out)
}
