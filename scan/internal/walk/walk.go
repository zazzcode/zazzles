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
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"

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
	// Config and Templates are allow-listed project artifacts, sorted by path.
	Config    []string
	Templates []string
	// Deploy is the deployment-file allow-list, sorted by path.
	Deploy []string
	// Unread are allow-listed paths that were not opened: a symlink or a
	// file over the size limit.
	Unread []string
	// Truncated names each allow-list ("config", "deploy") that passed 200
	// files. The files after the limit are not read.
	Truncated []string
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
	var artifacts []string
	composers := map[string]bool{}

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

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.Name() == "composer.json" {
			composers[filepath.ToSlash(filepath.Dir(rel))] = true
		}
		if entry.Type()&fs.ModeSymlink != 0 && (deployPath(rel) || configFileName(filepath.Base(rel))) {
			result.Unread = append(result.Unread, rel)
			return nil
		}
		switch filepath.Ext(rel) {
		case ".json", ".yaml", ".twig":
			artifacts = append(artifacts, rel)
		}
		if configFileName(filepath.Base(rel)) && filepath.Ext(rel) != ".yaml" && entry.Type().IsRegular() {
			artifacts = append(artifacts, rel)
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		result.Examined++
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > fileCap && (deployPath(rel) || configFileName(filepath.Base(rel))) {
			result.Unread = append(result.Unread, rel)
			return nil
		}
		if deployPath(rel) {
			result.noteDeploy(rel)
		}

		language, ok := lang.Detect(rel)
		if !ok {
			result.Unsupported++
			return nil
		}

		result.Files = append(result.Files, File{Path: rel, Language: language, Size: info.Size()})
		result.ByLanguage[language]++
		return nil
	})
	if err != nil {
		return nil, err
	}
	result.projectArtifacts(artifacts, composers)

	sort.Slice(result.Files, func(i, j int) bool { return result.Files[i].Path < result.Files[j].Path })
	sort.Strings(result.SkippedDirs)
	sort.Strings(result.Deploy)
	sort.Strings(result.Unread)
	return result, nil
}

func (r *Result) projectArtifacts(files []string, composers map[string]bool) {
	for _, file := range files {
		for dir := path.Dir(file); ; dir = path.Dir(dir) {
			if composers[dir] && !underComposerVar(dir, composers) {
				rel := file
				if dir != "." {
					rel = strings.TrimPrefix(file, dir+"/")
				}
				switch {
				case projectConfig(rel):
					r.Config = append(r.Config, file)
				case strings.HasPrefix(rel, "templates/") && path.Ext(rel) == ".twig":
					r.Templates = append(r.Templates, file)
				}
				break
			}
			if dir == "." {
				break
			}
		}
	}
	sort.Strings(r.Config)
	if len(r.Config) > listCap {
		r.Truncated = append(r.Truncated, "config")
		sort.Strings(r.Truncated)
		r.Config = r.Config[:listCap]
	}
	sort.Strings(r.Templates)
}

const listCap = 200
const fileCap = 256 << 10

func (r *Result) noteDeploy(rel string) {
	if len(r.Deploy) < listCap {
		r.Deploy = append(r.Deploy, rel)
		return
	}
	if !slices.Contains(r.Truncated, "deploy") {
		r.Truncated = append(r.Truncated, "deploy")
	}
}

func underComposerVar(dir string, composers map[string]bool) bool {
	for dir != "." {
		parent := path.Dir(dir)
		if path.Base(dir) == "var" && composers[parent] {
			return true
		}
		dir = parent
	}
	return false
}

func projectConfig(rel string) bool {
	switch rel {
	case "composer.json", "config/routes.yaml", "config/services.yaml", "config/packages/twig.yaml",
		"config/packages/doctrine.yaml", "config/packages/security.yaml",
		"config/packages/framework.yaml", "config/packages/web_profiler.yaml",
		".env", ".env.local", ".env.prod", ".env.prod.local":
		return true
	}
	return path.Dir(rel) == "config/routes" && path.Ext(rel) == ".yaml"
}

func configFileName(base string) bool {
	switch base {
	case ".env", ".env.local", ".env.prod", ".env.prod.local", "framework.yaml", "web_profiler.yaml":
		return true
	}
	return false
}

// deployPath is the deployment allow-list. A schedule's script is opened
// later, only when a parsed line names a project file.
func deployPath(rel string) bool {
	base := path.Base(rel)
	if base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile.") || strings.HasSuffix(base, ".dockerfile") || base == ".htaccess" || base == "crontab" || strings.HasSuffix(base, ".cron") {
		return true
	}
	dir := path.Dir(rel)
	if path.Base(dir) == "cron.d" {
		return true
	}
	if (strings.HasSuffix(base, ".conf") || base == "php.ini") && deployDir(dir) {
		return true
	}
	return false
}

func deployDir(dir string) bool {
	for _, root := range []string{"docker", ".docker", "deploy", "config/apache", "config/nginx", "apache", "nginx", "etc"} {
		if dir == root || strings.HasPrefix(dir, root+"/") {
			return true
		}
	}
	return false
}
