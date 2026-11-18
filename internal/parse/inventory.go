package parse

import (
	"path/filepath"
	"strings"

	"github.com/zazzcode/zazzles/internal/lang"
	"github.com/zazzcode/zazzles/internal/walk"
)

// Inventory is the single walk result shared by every language runner. Runners
// filter its files by language; none walks the target again.
type Inventory struct {
	Root  string
	Files []walk.File
}

// Options controls optional acquisition discovery without changing Python adapters.
type Options struct{ DiscoverRoutes bool }

// Languages names the runners one analysis needs; Assemble merges them in
// this field order.
type Languages struct{ JavaScript, Python, PHP bool }

// NormalizeEntry cleans an --entry path to the slash form runners select by;
// an empty or "." entry means a full scan.
func NormalizeEntry(entry string) string {
	entry = filepath.ToSlash(filepath.Clean(entry))
	if entry == "." {
		return ""
	}
	return entry
}

// Runners keeps the entry modes: a Python or PHP entry runs only that language
// and any other entry runs only JS/TS. A full scan always runs JS/TS, which
// owns the base report, plus each other language the inventory contains.
// The entry must already be normalized.
func (inv Inventory) Runners(entry string) Languages {
	switch ext := strings.ToLower(filepath.Ext(entry)); {
	case ext == ".py":
		return Languages{Python: true}
	case ext == ".php" || ext == ".phtml":
		return Languages{PHP: true}
	case entry != "":
		return Languages{JavaScript: true}
	}
	return Languages{JavaScript: true, Python: inv.HasLanguage(lang.Python), PHP: inv.HasLanguage(lang.PHP)}
}

func (inv Inventory) HasLanguage(languages ...lang.Language) bool {
	for _, f := range inv.Files {
		for _, l := range languages {
			if f.Language == l {
				return true
			}
		}
	}
	return false
}
