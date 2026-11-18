package langjs

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// maxPackageFileBytes bounds a manifest or lockfile read. Workspace lockfiles are
// routinely larger than the 2 MiB text bound; anything over this yields no version.
const maxPackageFileBytes = 16 << 20

// packageLockOrder is the lockfile precedence inside one directory: npm's own
// shrinkwrap and lock, then pnpm, then Yarn.
var packageLockOrder = []string{"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"}

// packageFile is one parsed manifest or lockfile, cached for the scan.
type packageFile struct {
	// broken marks a manifest that exists but cannot be read as one; nothing is
	// resolved through it, and ancestors are not consulted in its place.
	broken       bool
	dependencies map[string]string            // package.json dependencies
	npm          map[string]string            // npm lock v2/v3 package path -> version
	npmV1        map[string]string            // npm lock v1 dependency name -> version
	yarn         []yarnEntry                  // yarn.lock entries
	pnpm         map[string]map[string]string // pnpm importer -> dependency -> version
}

// packageResolution is a dependency version and the file that established it.
type packageResolution struct {
	Version string
	File    string
}

func joinDir(dir, name string) string {
	if dir == "." || dir == "" {
		return name
	}
	return dir + "/" + name
}

// ancestorDirs lists the directories of file from the nearest to the scan root
// (".").
func ancestorDirs(file string) []string {
	dir := path.Dir(filepath.ToSlash(file))
	out := []string{dir}
	for dir != "." && dir != "/" {
		dir = path.Dir(dir)
		out = append(out, dir)
	}
	return out
}

// loadPackageFile reads and parses one manifest or lockfile through the
// sandboxed text reader. Unreadable, oversized or malformed files are cached as
// absent so a scan never re-reads them.
func (s *moduleSet) loadPackageFile(file string) *packageFile {
	if p, ok := s.packageFiles[file]; ok {
		return p
	}
	if s.packageFiles == nil {
		s.packageFiles = map[string]*packageFile{}
	}
	var parsed *packageFile
	if e, ok := s.readBounded(file, maxPackageFileBytes); ok {
		switch path.Base(file) {
		case "package.json":
			parsed = parseManifest(e.Text)
		case "package-lock.json", "npm-shrinkwrap.json":
			parsed = parseNPMLock(e.Text)
		case "pnpm-lock.yaml":
			parsed = parsePNPMLock(e.Text)
		case "yarn.lock":
			parsed = parseYarnLock(e.Text)
		}
	}
	s.packageFiles[file] = parsed
	return parsed
}

func parseManifest(text string) *packageFile {
	var manifest struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if json.Unmarshal([]byte(text), &manifest) != nil {
		return &packageFile{broken: true}
	}
	if manifest.Dependencies == nil {
		manifest.Dependencies = map[string]string{}
	}
	return &packageFile{dependencies: manifest.Dependencies}
}

func parseNPMLock(text string) *packageFile {
	var lock struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if json.Unmarshal([]byte(text), &lock) != nil {
		return nil
	}
	p := &packageFile{npm: map[string]string{}, npmV1: map[string]string{}}
	for key, entry := range lock.Packages {
		if entry.Version != "" {
			p.npm[key] = entry.Version
		}
	}
	for name, entry := range lock.Dependencies {
		if entry.Version != "" {
			p.npmV1[name] = entry.Version
		}
	}
	return p
}

// declaration returns the nearest ancestor manifest, from the source file's
// package directory upward, that declares the dependency, with its declared
// string (a range or an exact pin) and path.
func (s *moduleSet) declaration(file, name string) (declared, manifest string) {
	for _, dir := range ancestorDirs(file) {
		manifest := joinDir(dir, "package.json")
		p := s.loadPackageFile(manifest)
		if p != nil && p.broken {
			return "", ""
		}
		if p != nil && p.dependencies[name] != "" {
			return p.dependencies[name], manifest
		}
	}
	return "", ""
}

// packageDir is the nearest ancestor directory of file holding a readable
// package.json, or the scan root.
func (s *moduleSet) packageDir(file string) string {
	for _, dir := range ancestorDirs(file) {
		if s.loadPackageFile(joinDir(dir, "package.json")) != nil {
			return dir
		}
	}
	return "."
}

// resolvePackage resolves a dependency for a source file. A lockfile
// from the file's package directory upward is authoritative; otherwise the
// nearest manifest that declares the dependency supplies its declared string,
// which callers accept as a version only when it is an exact x.y.z. Ranges,
// ambiguous lock entries and unreadable files establish nothing.
func (s *moduleSet) resolvePackage(file, name string) packageResolution {
	declared, manifest := s.declaration(file, name)
	pkgDir := s.packageDir(file)
	dirs := ancestorDirs(joinDir(pkgDir, "x"))
	for _, dir := range dirs {
		for _, lock := range packageLockOrder {
			lockFile := joinDir(dir, lock)
			p := s.loadPackageFile(lockFile)
			if p == nil {
				continue
			}
			rel := relativeDir(dir, pkgDir)
			if v := p.lockVersion(path.Base(lock), rel, name, declared); v != "" {
				return packageResolution{v, lockFile}
			}
		}
	}
	if declared != "" {
		return packageResolution{declared, manifest}
	}
	return packageResolution{}
}

// relativeDir is dir's descendant `to` expressed relative to dir; "" for dir itself.
func relativeDir(dir, to string) string {
	if dir == "." || dir == "" {
		if to == "." {
			return ""
		}
		return to
	}
	return strings.TrimPrefix(strings.TrimPrefix(to, dir), "/")
}

// packageVersion resolves the version of name for a source file; "" when unknown.
func (s *moduleSet) packageVersion(file, name string) string {
	return s.resolvePackage(file, name).Version
}

// lockVersion looks a dependency up in one parsed lockfile for the workspace at
// rel (relative to the lock's directory, "" for the lock's own root).
func (p *packageFile) lockVersion(kind, rel, name, declared string) string {
	switch kind {
	case "npm-shrinkwrap.json", "package-lock.json":
		// Node resolution order: the workspace's own node_modules, each ancestor's, then the root's.
		for dir := rel; ; dir = path.Dir(dir) {
			if v := p.npm[joinDir(dir, "node_modules/"+name)]; v != "" {
				return v
			}
			if dir == "" || dir == "." || dir == "/" {
				break
			}
		}
		if len(p.npm) == 0 || rel == "" {
			return p.npmV1[name]
		}
		return ""
	case "pnpm-lock.yaml":
		importer := rel
		if importer == "" {
			importer = "."
		}
		if deps, ok := p.pnpm[importer]; ok {
			return deps[name]
		}
		// A workspace the lock does not list as an importer has no pnpm-specific resolution.
		return ""
	case "yarn.lock":
		return p.yarnVersion(name, declared)
	}
	return ""
}

// declarationEvidence anchors a dependency fact to the manifest it came from: the
// nearest manifest declaring the dependency, else the file's package manifest,
// else the lockfile that supplied the version.
func (s *moduleSet) declarationEvidence(file, pkg string, resolution packageResolution) (analysis.Evidence, bool) {
	anchor := ""
	if _, manifest := s.declaration(file, pkg); manifest != "" {
		anchor = manifest
	} else if manifest := joinDir(s.packageDir(file), "package.json"); s.loadPackageFile(manifest) != nil {
		anchor = manifest
	} else {
		anchor = resolution.File
	}
	e, ok := s.readBounded(anchor, maxPackageFileBytes)
	if !ok {
		return analysis.Evidence{}, false
	}
	e.Kind, e.Text = "dependency_declaration", fmt.Sprintf("%q resolves to %q", pkg, resolution.Version)
	return e, true
}
