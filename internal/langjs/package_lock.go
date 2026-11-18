package langjs

import "strings"

// yarnEntry is one yarn.lock record: the specifiers (`name@range`) it resolves
// and the single version they share.
type yarnEntry struct {
	name    string
	ranges  []string
	version string
}

func unquoteYAML(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' && s[len(s)-1] == '"' || s[0] == '\'' && s[len(s)-1] == '\'') {
		return s[1 : len(s)-1]
	}
	return s
}

// splitYAMLPair splits `key: value` at the first colon that ends the key; the
// key may be quoted (`'@scope/pkg': 1.2.3`).
func splitYAMLPair(line string) (key, value string) {
	if line == "" {
		return "", ""
	}
	if line[0] == '\'' || line[0] == '"' {
		if end := strings.IndexByte(line[1:], line[0]); end >= 0 {
			rest := strings.TrimSpace(line[end+2:])
			return line[1 : end+1], strings.TrimSpace(strings.TrimPrefix(rest, ":"))
		}
	}
	if i := strings.Index(line, ":"); i >= 0 {
		return line[:i], strings.TrimSpace(line[i+1:])
	}
	return line, ""
}

// lockVersionToken keeps the version part of a pnpm value, dropping peer-suffix
// groups (`1.2.3(react@18)`, `1.2.3_react@18`). Links and other non-version
// values yield "".
func lockVersionToken(value string) string {
	value = unquoteYAML(value)
	if i := strings.IndexAny(value, "(_"); i >= 0 {
		value = value[:i]
	}
	if value == "" || strings.ContainsAny(value, ":/") {
		return ""
	}
	return value
}

// parsePNPMLock reads the dependency versions of each importer from pnpm's
// lockfile formats 5, 6 and 9. Only the `dependencies` group of an importer (or
// of the root, in the format-5 layout) is read; everything else is ignored.
func parsePNPMLock(text string) *packageFile {
	p := &packageFile{pnpm: map[string]map[string]string{}}
	record := func(importer, name, version string) {
		if version = lockVersionToken(version); version != "" {
			if p.pnpm[importer] == nil {
				p.pnpm[importer] = map[string]string{}
			}
			p.pnpm[importer][name] = version
		}
	}
	var section, importer, group, dependency string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, value := splitYAMLPair(trim)
		switch {
		case indent == 0:
			section, importer, group, dependency = key, "", "", ""
			if section == "dependencies" {
				importer, group = ".", "dependencies"
			}
		case section == "dependencies" && indent == 2:
			record(".", key, value)
		case section == "importers" && indent == 2:
			importer, group, dependency = key, "", ""
			if p.pnpm[importer] == nil {
				p.pnpm[importer] = map[string]string{}
			}
		case section == "importers" && indent == 4:
			group, dependency = key, ""
		case section == "importers" && indent == 6 && group == "dependencies":
			if value != "" {
				record(importer, key, value)
			} else {
				dependency = key
			}
		case section == "importers" && indent == 8 && group == "dependencies" && dependency != "" && key == "version":
			record(importer, dependency, value)
		}
	}
	return p
}

// parseYarnLock reads yarn.lock entries of classic (v1) and Berry formats.
func parseYarnLock(text string) *packageFile {
	p := &packageFile{}
	var current *yarnEntry
	flush := func() {
		if current != nil && current.name != "" && current.version != "" {
			p.yarn = append(p.yarn, *current)
		}
		current = nil
	}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") {
			continue
		}
		if line[0] != ' ' {
			flush()
			if !strings.HasSuffix(trim, ":") {
				continue
			}
			current = &yarnEntry{}
			for _, spec := range strings.Split(strings.TrimSuffix(trim, ":"), ",") {
				spec = unquoteYAML(spec)
				at := strings.LastIndex(spec, "@")
				if at <= 0 {
					continue
				}
				name := spec[:at]
				if current.name == "" {
					current.name = name
				}
				if name == current.name {
					current.ranges = append(current.ranges, strings.TrimPrefix(spec[at+1:], "npm:"))
				}
			}
			continue
		}
		// The entry's own field sits at two spaces; a dependency such as
		// `version-compare "^1.0.0"` is deeper or has a longer key.
		if current != nil && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") {
			if key, value := yarnField(trim); key == "version" {
				current.version = unquoteYAML(value)
			}
		}
	}
	flush()
	return p
}

// yarnVersion resolves name in yarn.lock. With a declared range the entry that
// resolves exactly that specifier supplies the version; without one, the version
// is established only when every entry of the name agrees.
func (p *packageFile) yarnVersion(name, declared string) string {
	declared = strings.TrimPrefix(declared, "npm:")
	versions := map[string]bool{}
	for _, e := range p.yarn {
		if e.name != name {
			continue
		}
		if declared != "" {
			for _, r := range e.ranges {
				if r == declared {
					return e.version
				}
			}
			continue
		}
		versions[e.version] = true
	}
	if len(versions) == 1 {
		for v := range versions {
			return v
		}
	}
	return ""
}

// yarnField splits `version "1.2.3"` (classic) or `version: 1.2.3` (Berry).
func yarnField(line string) (key, value string) {
	if i := strings.IndexAny(line, " :"); i > 0 {
		return line[:i], strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line[i:]), ":"))
	}
	return line, ""
}
