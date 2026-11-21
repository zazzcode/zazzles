package langpy

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var pyYAMLRequirement = regexp.MustCompile(`(?i)^\s*py[-_]?yaml(?:\[[^\]]*\])?\s*==\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)\s*(?:[;#].*)?$`)
var pythonExactVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?$`)

func (s *pythonSet) pyYAMLVersion(file string) string {
	dir := filepath.Dir(filepath.FromSlash(file))
	for {
		if version, found := pythonPackageVersion(filepath.Join(s.root, dir)); found {
			return version
		}
		if dir == "." {
			return ""
		}
		dir = filepath.Dir(dir)
	}
}

func pythonPackageVersion(dir string) (string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false
	}
	found, unavailable := false, false
	pins := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		requirements := strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")
		if !requirements && name != "poetry.lock" && name != "uv.lock" {
			continue
		}
		found = true
		data, ok := readPythonManifest(dir, entry)
		if !ok {
			unavailable = true
			continue
		}
		if requirements {
			for _, line := range strings.Split(data, "\n") {
				if m := pyYAMLRequirement.FindStringSubmatch(line); m != nil {
					pins[m[1]] = true
				}
			}
		} else {
			addPythonLockPins(data, pins)
		}
	}
	if !unavailable && len(pins) == 1 {
		for pin := range pins {
			return pin, true
		}
	}
	return "", found
}

func readPythonManifest(dir string, entry os.DirEntry) (string, bool) {
	const limit = 1 << 20
	info, err := entry.Info()
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return "", false
	}
	file, err := os.Open(filepath.Join(dir, entry.Name()))
	if err != nil {
		return "", false
	}
	defer file.Close()
	current, err := file.Stat()
	if err != nil || !os.SameFile(info, current) {
		return "", false
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	return string(data), err == nil && len(data) <= limit
}

func addPythonLockPins(data string, pins map[string]bool) {
	var inPackage bool
	var name, version string
	flush := func() {
		if inPackage && strings.EqualFold(name, "pyyaml") && pythonExactVersion.MatchString(version) {
			pins[version] = true
		}
	}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			flush()
			inPackage, name, version = line == "[[package]]", "", ""
			continue
		}
		if !inPackage {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value, _, _ = strings.Cut(strings.TrimSpace(value), "#")
		value = strings.TrimSpace(value)
		if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
			continue
		}
		switch strings.TrimSpace(key) {
		case "name":
			name = value[1 : len(value)-1]
		case "version":
			version = value[1 : len(value)-1]
		}
	}
	flush()
}
