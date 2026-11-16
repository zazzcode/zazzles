package parse

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// tsConfig is the bounded part of a tsconfig.json / jsconfig.json the scanner
// reads: module path aliases and the project exclude list. Directories are
// relative to the scan root with forward slashes ("" for the root itself).
type tsConfig struct {
	file    string
	dir     string
	baseURL string // resolved directory, "" with hasBase false when absent
	hasBase bool
	paths   map[string][]string
	// pathsDir is the directory paths entries resolve against (baseUrl or the
	// declaring config's directory).
	pathsDir string
	exclude  []string
	hasExcl  bool
}

// jsoncClean removes // and /* */ comments outside strings and trailing commas,
// which tsconfig files commonly contain.
func jsoncClean(src []byte) []byte {
	out := make([]byte, 0, len(src))
	inString, escaped := false, false
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			out = append(out, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '/' {
			for i < len(src) && src[i] != '\n' {
				i++
			}
			out = append(out, '\n')
			continue
		}
		if c == '/' && i+1 < len(src) && src[i+1] == '*' {
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			i++
			continue
		}
		out = append(out, c)
	}
	// Trailing commas before } or ].
	clean := make([]byte, 0, len(out))
	inString, escaped = false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if inString {
			clean = append(clean, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
		}
		if c == ',' {
			j := i + 1
			for j < len(out) && (out[j] == ' ' || out[j] == '\n' || out[j] == '\r' || out[j] == '\t') {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				continue
			}
		}
		clean = append(clean, c)
	}
	return clean
}

type rawTSConfig struct {
	Extends         json.RawMessage `json:"extends"`
	CompilerOptions struct {
		BaseURL *string             `json:"baseUrl"`
		Paths   map[string][]string `json:"paths"`
	} `json:"compilerOptions"`
	Exclude *[]string `json:"exclude"`
}

// readTSConfig loads one config file (relative to root) and follows relative
// `extends` chains up to three levels. Package-name extends are ignored.
func readTSConfig(root, file string, depth int) *tsConfig {
	if depth > 3 {
		return nil
	}
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file)))
	if err != nil || len(src) > 1<<20 {
		return nil
	}
	var raw rawTSConfig
	if json.Unmarshal(jsoncClean(src), &raw) != nil {
		return nil
	}
	dir := path.Dir(file)
	if dir == "." {
		dir = ""
	}
	cfg := &tsConfig{file: file, dir: dir}
	var parents []string
	if len(raw.Extends) > 0 {
		var one string
		var many []string
		if json.Unmarshal(raw.Extends, &one) == nil {
			parents = []string{one}
		} else if json.Unmarshal(raw.Extends, &many) == nil {
			parents = many
		}
	}
	for _, p := range parents {
		if !strings.HasPrefix(p, ".") {
			continue
		}
		target := path.Clean(path.Join(dir, p))
		if !strings.HasSuffix(target, ".json") {
			target += ".json"
		}
		if strings.HasPrefix(target, "../") || target == ".." {
			continue
		}
		if parent := readTSConfig(root, target, depth+1); parent != nil {
			if parent.hasBase {
				cfg.baseURL, cfg.hasBase = parent.baseURL, true
			}
			if parent.paths != nil {
				cfg.paths, cfg.pathsDir = parent.paths, parent.pathsDir
			}
			if parent.hasExcl {
				cfg.exclude, cfg.hasExcl = parent.exclude, true
			}
		}
	}
	if raw.CompilerOptions.BaseURL != nil {
		cfg.baseURL, cfg.hasBase = cleanRel(path.Join(dir, *raw.CompilerOptions.BaseURL)), true
		if cfg.paths != nil {
			cfg.pathsDir = cfg.baseURL
		}
	}
	if raw.CompilerOptions.Paths != nil {
		cfg.paths = raw.CompilerOptions.Paths
		cfg.pathsDir = dir
		if cfg.hasBase {
			cfg.pathsDir = cfg.baseURL
		}
	}
	if raw.Exclude != nil {
		cfg.exclude, cfg.hasExcl = *raw.Exclude, true
	}
	return cfg
}

func cleanRel(p string) string {
	p = path.Clean(p)
	if p == "." {
		return ""
	}
	return p
}

// tsConfigFor returns the nearest tsconfig.json or jsconfig.json at or above
// the directory of file, within the scan root.
func (s *moduleSet) tsConfigFor(file string) *tsConfig {
	if s.tsConfigs == nil {
		s.tsConfigs = map[string]*tsConfig{}
	}
	for _, dir := range ancestorDirs(file) {
		if cfg, ok := s.tsConfigs[dir]; ok {
			if cfg != nil {
				return cfg
			}
			continue
		}
		var found *tsConfig
		for _, name := range []string{"tsconfig.json", "jsconfig.json"} {
			if found = readTSConfig(s.root, joinDir(dir, name), 0); found != nil {
				break
			}
		}
		s.tsConfigs[dir] = found
		if found != nil {
			return found
		}
	}
	return nil
}

// aliasBases maps a non-relative specifier through the nearest config's paths
// (and then its baseUrl). It returns candidate module bases relative to the scan
// root, without extension. A specifier no alias matches returns nothing.
func (s *moduleSet) aliasBases(from, spec string) []string {
	cfg := s.tsConfigFor(from)
	if cfg == nil {
		return nil
	}
	var out []string
	if cfg.paths != nil {
		best, bestPrefix := "", -1
		keys := make([]string, 0, len(cfg.paths))
		for k := range cfg.paths {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if key == spec {
				best, bestPrefix = key, len(key)+1
				break
			}
			if star := strings.Index(key, "*"); star >= 0 && strings.Count(key, "*") == 1 {
				prefix, suffix := key[:star], key[star+1:]
				if strings.HasPrefix(spec, prefix) && strings.HasSuffix(spec, suffix) && len(spec) >= len(prefix)+len(suffix) && len(prefix) > bestPrefix {
					best, bestPrefix = key, len(prefix)
				}
			}
		}
		if bestPrefix >= 0 {
			star := strings.Index(best, "*")
			matched := ""
			if star >= 0 {
				matched = spec[star : len(spec)-(len(best)-star-1)]
			}
			for _, target := range cfg.paths[best] {
				target = strings.Replace(target, "*", matched, 1)
				resolved := cleanRel(path.Join(cfg.pathsDir, target))
				if !strings.HasPrefix(resolved, "../") && resolved != ".." {
					out = append(out, resolved)
				}
			}
			return out
		}
	}
	if cfg.hasBase {
		resolved := cleanRel(path.Join(cfg.baseURL, spec))
		if !strings.HasPrefix(resolved, "../") {
			out = append(out, resolved)
		}
	}
	return out
}

// moduleCandidates lists the files a specifier may name, in resolution order.
// Relative specifiers keep their established order; aliases add the TSX/JSX
// forms TypeScript resolves.
func (s *moduleSet) moduleCandidates(m *sourceModule, spec string) []string {
	var bases []string
	if strings.HasPrefix(spec, ".") {
		bases = []string{filepath.ToSlash(filepath.Join(filepath.Dir(m.file), spec))}
	} else {
		bases = s.aliasBases(m.file, spec)
	}
	var out []string
	for _, base := range bases {
		out = append(out, base, base+".ts", base+".tsx", base+".js", base+".mjs", base+"/index.ts", base+"/index.js")
		out = append(out, base+".jsx", base+"/index.tsx", base+"/index.jsx")
	}
	return out
}
