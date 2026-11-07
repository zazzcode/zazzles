package parse

import (
	"encoding/json"
	"fmt"
)

func (s *moduleSet) packageVersion(name string) string {
	// A lockfile is authoritative for resolved versions. A literal manifest pin
	// is accepted only when no lock entry exists; ranges never establish a version.
	if file, ok := s.readText("package-lock.json"); ok {
		var lock struct {
			Packages map[string]struct {
				Version string `json:"version"`
			} `json:"packages"`
			Dependencies map[string]struct {
				Version string `json:"version"`
			} `json:"dependencies"`
		}
		if json.Unmarshal([]byte(file.Text), &lock) == nil {
			if p := lock.Packages["node_modules/"+name]; p.Version != "" {
				return p.Version
			}
			if p := lock.Dependencies[name]; p.Version != "" {
				return p.Version
			}
		}
	}
	if file, ok := s.readText("package.json"); ok {
		var manifest struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if json.Unmarshal([]byte(file.Text), &manifest) == nil {
			return manifest.Dependencies[name]
		}
	}
	return ""
}

// sanitizerAdvisory is a published bypass of a sanitizer's default configuration.
// It applies only to an exact resolved version in [introduced, fixed); a version
// range or custom options never match, so they keep their ordinary contract.
type sanitizerAdvisory struct {
	library, id         string
	introduced, fixed   [3]int
	reference, behavior string
}

var sanitizerAdvisories = []sanitizerAdvisory{
	{"marked", "CVE-2016-10531", [3]int{0, 0, 0}, [3]int{0, 3, 6}, "https://github.com/advisories/GHSA-vfvf-mqq8-rwqc", "sanitize: true lets entity-encoded javascript: link URIs through"},
	{"sanitize-html", "CVE-2016-1000237", [3]int{0, 0, 0}, [3]int{1, 4, 3}, "https://advisories.gitlab.com/pkg/npm/sanitize-html/CVE-2016-1000237", "sanitization is not applied recursively"},
	{"sanitize-html", "CVE-2026-44990", [3]int{2, 17, 3}, [3]int{2, 17, 4}, "https://github.com/advisories/GHSA-rpr9-rxv7-x643", "default options pass xmp raw text through as live markup"},
}

// bypassAdvisory returns the advisory affecting the pinned version of a library.
func (s *moduleSet) bypassAdvisory(library string) (sanitizerAdvisory, bool) {
	version, ok := exactVersion(s.packageVersion(library))
	if !ok {
		return sanitizerAdvisory{}, false
	}
	for _, a := range sanitizerAdvisories {
		if a.library == library && !versionLess(version, a.introduced) && versionLess(version, a.fixed) {
			return a, true
		}
	}
	return sanitizerAdvisory{}, false
}

func exactVersion(version string) ([3]int, bool) {
	var v [3]int
	if n, err := fmt.Sscanf(version, "%d.%d.%d", &v[0], &v[1], &v[2]); n != 3 || err != nil || fmt.Sprintf("%d.%d.%d", v[0], v[1], v[2]) != version {
		return v, false
	}
	return v, true
}

func versionLess(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
