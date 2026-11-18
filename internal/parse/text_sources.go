package parse

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/walk"
)

// TextSources reads non-code text files (templates, schemas) inside one scan root and keeps each
// file it reads or is given as a snapshot, so later reads return the same evidence and the runner
// can list every snapshot in the report files.
type TextSources struct {
	root  string
	files map[string]analysis.Evidence
}

// NewTextSources returns an empty text source set for root.
func NewTextSources(root string) *TextSources {
	return &TextSources{root: root, files: map[string]analysis.Evidence{}}
}

// Root is the scan root the set reads under.
func (t *TextSources) Root() string { return t.root }

// Read reads file (slash-separated, relative to the root) with the default 2 MiB limit.
func (t *TextSources) Read(file string) (analysis.Evidence, bool) {
	return t.ReadBounded(file, 2<<20)
}

// ReadBounded reads a regular file inside the scan root, outside skipped
// directories and symlink escapes, no larger than limit bytes.
func (t *TextSources) ReadBounded(file string, limit int64) (analysis.Evidence, bool) {
	file = filepath.ToSlash(filepath.Clean(file))
	if file == "." || filepath.IsAbs(file) || strings.HasPrefix(file, "../") {
		return analysis.Evidence{}, false
	}
	for _, part := range strings.Split(file, "/") {
		for _, skipped := range walk.DefaultSkipDirs {
			if part == skipped {
				return analysis.Evidence{}, false
			}
		}
	}
	if e, ok := t.files[file]; ok {
		return e, true
	}
	path := filepath.Join(t.root, filepath.FromSlash(file))
	real, err := filepath.EvalSymlinks(path)
	root, rootErr := filepath.EvalSymlinks(t.root)
	if err != nil || rootErr != nil {
		return analysis.Evidence{}, false
	}
	relative, err := filepath.Rel(root, real)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return analysis.Evidence{}, false
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return analysis.Evidence{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return analysis.Evidence{}, false
	}
	e := analysis.Evidence{Kind: "template", Text: string(data), SHA256: fmt.Sprintf("%x", sha256.Sum256(data)),
		Span: analysis.Span{File: file, StartLine: 1, EndLine: strings.Count(string(data), "\n") + 1, EndByte: len(data)}}
	t.files[file] = e
	return e, true
}

// Add records e as the snapshot of file, replacing an earlier one.
func (t *TextSources) Add(file string, e analysis.Evidence) { t.files[file] = e }

// Get returns the snapshot of file, if the set holds one.
func (t *TextSources) Get(file string) (analysis.Evidence, bool) {
	e, ok := t.files[file]
	return e, ok
}

// Files lists the files with snapshots, sorted.
func (t *TextSources) Files() []string {
	files := make([]string, 0, len(t.files))
	for file := range t.files {
		files = append(files, file)
	}
	sort.Strings(files)
	return files
}

// SimpleTemplateField matches a dotted field path, the only template expression treated as a plain field read.
var SimpleTemplateField = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*$`)

// TextRange returns e narrowed to e.Text[start:end] as kind, with byte and line spans.
func TextRange(e analysis.Evidence, start, end int, kind string) analysis.Evidence {
	before, part := e.Text[:start], e.Text[start:end]
	e.Kind = kind
	e.Span.StartByte, e.Span.EndByte = start, end
	e.Span.StartLine = strings.Count(before, "\n") + 1
	e.Span.EndLine = e.Span.StartLine + strings.Count(part, "\n")
	e.Text = part
	return e
}
