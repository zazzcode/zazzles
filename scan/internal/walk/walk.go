// Package walk traverses a repository and selects the source files the rest of
// the pipeline consumes.
//
// Traversal is deterministic: results are sorted by path and do not depend on
// filesystem enumeration order, because every downstream artifact -- manifests,
// findings, fingerprints -- depends on a stable input order.
//
// Nothing is dropped silently. Unsupported files are counted, and every
// directory that was not descended into is reported.
package walk

import (
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// File is one source file selected for processing.
type File struct {
	// Path is relative to the walk root and uses forward slashes on every
	// platform, so paths are stable in graph and findings output.
	Path     string
	Language lang.Language
	Size     int64
}

// DefaultSkipDirs are directory names never descended into. VCS metadata,
// installed dependencies, and build output are not the target's own code.
//
// testdata is deliberately not skipped: fixture and example code is copied into
// production often enough that hiding it would hide findings.
var DefaultSkipDirs = []string{
	".git", ".hg", ".svn",
	"node_modules", "vendor",
	"dist", "build", "out", "target",
	".next", ".nuxt", ".output", ".cache",
	"coverage", ".venv", "venv", "__pycache__",
}

// Options controls a walk.
type Options struct {
	// SkipDirs are additional directory names to skip, on top of DefaultSkipDirs.
	SkipDirs []string
}

// Result is the outcome of a walk.
type Result struct {
	// Root is the path the walk started from.
	Root string
	// Files are the supported source files, sorted by path.
	Files []File
	// ByLanguage counts the supported files per language.
	ByLanguage map[lang.Language]int
	// Examined counts every regular file considered, supported or not.
	Examined int
	// Unsupported counts regular files whose language scan does not support.
	Unsupported int
	// SkippedDirs are the directories that were not descended into, sorted.
	SkippedDirs []string
}

// Walk returns the supported source files under root.
//
// An unreadable entry aborts the walk with an error rather than silently
// shrinking the input.
func Walk(root string, opts Options) (*Result, error) {
	skip := make(map[string]struct{}, len(DefaultSkipDirs)+len(opts.SkipDirs))
	for _, dir := range DefaultSkipDirs {
		skip[dir] = struct{}{}
	}
	for _, dir := range opts.SkipDirs {
		skip[dir] = struct{}{}
	}

	result := &Result{Root: root, ByLanguage: map[lang.Language]int{}}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			if path == root {
				return nil
			}
			if _, ok := skip[entry.Name()]; ok {
				result.SkippedDirs = append(result.SkippedDirs, path)
				return fs.SkipDir
			}
			return nil
		}

		if !entry.Type().IsRegular() {
			return nil
		}

		result.Examined++

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		language, ok := lang.Detect(rel)
		if !ok {
			result.Unsupported++
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			return err
		}

		result.Files = append(result.Files, File{Path: rel, Language: language, Size: info.Size()})
		result.ByLanguage[language]++
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	sort.Strings(result.SkippedDirs)
	return result, nil
}
