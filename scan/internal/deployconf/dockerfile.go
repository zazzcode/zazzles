package deployconf

import (
	"encoding/json"
	"path"
	"strings"
)

// DockerImage is the literal path mapping and the instructions the
// configuration checks read from the final build stage.
type DockerImage struct {
	File string
	// FromLine is the line of the FROM that starts the deployed stage.
	FromLine int
	// Paths are COPY and ADD destinations in instruction order.
	Paths       []PathMapping
	Owners      []Ownership
	Schedules   []ScheduleLine
	Modules     []Directive
	EnvFiles    []PathMapping
	User        string
	WorkDir     string
	CronInstall []CronInstall
	Gaps        []Gap

	isDir func(string) bool
}

// Dockerfile reads literal WORKDIR, COPY, ADD, USER and RUN instructions.
// An operand with a build argument or a glob is unresolved. isDir reports
// whether a COPY source is a project directory. It may be nil, and then only
// "." and a source with a trailing slash are directories.
func Dockerfile(file string, src []byte, isDir func(string) bool) DockerImage {
	img := DockerImage{File: file, FromLine: 1, User: "root", WorkDir: "/", isDir: isDir}
	if tooBig(src) {
		img.Gaps = unread(file)
		return img
	}
	for _, row := range continuedLines(src) {
		text := stripComment(row.text, "#")
		toks := fieldsQuoted(text)
		if len(toks) == 0 {
			continue
		}
		switch op := strings.ToUpper(toks[0]); op {
		case "FROM":
			// Only the last stage is the deployed image.
			img = DockerImage{File: file, FromLine: row.num, User: "root", WorkDir: "/", isDir: isDir, Gaps: img.Gaps}
		case "WORKDIR":
			if len(toks) > 1 && literalOperand(toks[1]) {
				img.WorkDir = resolveDocker(img.WorkDir, unquote(toks[1]))
			} else if len(toks) > 1 {
				img.gap(row.num, "WORKDIR operand is not literal")
			}
		case "USER":
			if len(toks) > 1 && literalOperand(toks[1]) {
				img.User = userName(unquote(toks[1]))
			}
		case "COPY", "ADD":
			img.copy(row.num, op, copyOperands(text, toks[1:]))
		case "RUN":
			lead := strings.Index(text, toks[0]) + len(toks[0])
			for _, seg := range shellSegments(text[lead:]) {
				img.run(row.at(lead+seg.off), seg.text)
			}
		}
	}
	return img
}

func (img *DockerImage) gap(line int, detail string) {
	img.Gaps = append(img.Gaps, Gap{Kind: "deploy_mapping_unresolved", Detail: detail, File: img.File, Line: line})
}

// copyOperands returns the flags and paths of a COPY in either its shell or
// its JSON array form.
func copyOperands(text string, toks []string) []string {
	if i := strings.IndexByte(text, '['); i >= 0 && strings.HasSuffix(strings.TrimSpace(text), "]") {
		var list []string
		if json.Unmarshal([]byte(text[i:]), &list) == nil {
			var flags []string
			for _, t := range toks {
				if !strings.HasPrefix(t, "--") {
					break
				}
				flags = append(flags, t)
			}
			return append(flags, list...)
		}
	}
	return unquoteAll(toks)
}

func (img *DockerImage) copy(line int, op string, args []string) {
	chown := ""
	var paths []string
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "--chown="):
			chown = userName(a[len("--chown="):])
		case strings.HasPrefix(a, "--from="):
			img.gap(line, "COPY --from takes files from another build stage")
			return
		case strings.HasPrefix(a, "--"):
		default:
			paths = append(paths, a)
		}
	}
	if len(paths) < 2 || (op == "ADD" && strings.Contains(paths[0], "://")) {
		return
	}
	dst, srcs := paths[len(paths)-1], paths[:len(paths)-1]
	if !literalOperand(dst) {
		img.gap(line, "COPY or ADD destination is not literal")
		return
	}
	dstAbs := resolveDocker(img.WorkDir, dst)
	dstDir := len(srcs) > 1 || strings.HasSuffix(dst, "/") || dst == "." || dstAbs == img.WorkDir || img.mappedDir(dstAbs)
	for _, src := range srcs {
		if !literalOperand(src) || escapes(src) {
			img.gap(line, "COPY or ADD operand is not a literal project path")
			continue
		}
		clean := strings.TrimPrefix(path.Clean(src), "/")
		if clean == "" {
			clean = "."
		}
		target := dstAbs
		if dstDir && !img.sourceDir(src) {
			target = path.Join(dstAbs, path.Base(clean))
		}
		m := PathMapping{Dst: target, Src: clean, Line: line}
		img.Paths = append(img.Paths, m)
		if envName(target) {
			img.EnvFiles = append(img.EnvFiles, m)
		}
		if chown != "" {
			img.Owners = append(img.Owners, Ownership{File: img.File, Line: line, User: chown, Path: target, Recursive: true})
		}
	}
}

func (img *DockerImage) sourceDir(src string) bool {
	if src == "." || strings.HasSuffix(src, "/") {
		return true
	}
	return img.isDir != nil && img.isDir(path.Clean(src))
}

// mappedDir reports that an earlier COPY made dst a directory.
func (img *DockerImage) mappedDir(dst string) bool {
	for _, m := range img.Paths {
		if m.Dst == dst && img.sourceDir(m.Src) || strings.HasPrefix(m.Dst, dst+"/") {
			return true
		}
	}
	return false
}

// ProjectPath maps a container path to the project path a COPY put there.
// The longest destination wins and, between equal ones, the later COPY.
func (img DockerImage) ProjectPath(container string) (string, bool) {
	container = path.Clean(container)
	best := -1
	for i, m := range img.Paths {
		if container != m.Dst && !strings.HasPrefix(container, strings.TrimRight(m.Dst, "/")+"/") {
			continue
		}
		if best < 0 || len(m.Dst) >= len(img.Paths[best].Dst) {
			best = i
		}
	}
	if best < 0 {
		return "", false
	}
	m := img.Paths[best]
	rest := strings.TrimPrefix(strings.TrimPrefix(container, strings.TrimRight(m.Dst, "/")), "/")
	return path.Join(m.Src, rest), true
}

// Installed reports whether a project file is copied under a web-server
// configuration directory, and the line of that COPY.
func (img DockerImage) Installed(file string) (int, bool) {
	for _, m := range img.Paths {
		if !serverConfDir(m.Dst) {
			continue
		}
		if file == m.Src || strings.HasPrefix(file, m.Src+"/") {
			return m.Line, true
		}
	}
	return 0, false
}

// run reads one shell command of a RUN instruction.
func (img *DockerImage) run(line int, text string) {
	toks := unquoteAll(fieldsQuoted(text))
	if len(toks) == 0 {
		return
	}
	switch toks[0] {
	case "a2enmod":
		for _, tok := range toks[1:] {
			if tok != "" && !strings.HasPrefix(tok, "-") {
				img.Modules = append(img.Modules, Directive{File: img.File, Line: line, Name: "a2enmod", Values: []string{tok}})
			}
		}
	case "chown", "chmod":
		img.own(line, toks)
	case "echo":
		if body, ok := cronEcho(text); ok {
			for _, job := range Cron(img.File, []byte(body), true) {
				job.Line = line
				img.Schedules = append(img.Schedules, job)
			}
		}
	case "crontab":
		if len(toks) > 1 && !strings.HasPrefix(toks[1], "-") && literalOperand(toks[1]) {
			img.CronInstall = append(img.CronInstall, CronInstall{File: img.File, Line: line, User: img.User, Path: resolveDocker(img.WorkDir, toks[1])})
		}
	}
}

func (img *DockerImage) own(line int, toks []string) {
	recursive := false
	var rest []string
	for _, a := range toks[1:] {
		switch {
		case a == "--recursive":
			recursive = true
		case strings.HasPrefix(a, "--"):
		case toks[0] == "chmod" && len(rest) == 0 && symbolicRemoval(a):
			rest = append(rest, a)
		case strings.HasPrefix(a, "-"):
			recursive = recursive || strings.Contains(a, "R")
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) < 2 {
		return
	}
	for _, target := range rest[1:] {
		if !literalOperand(target) {
			continue
		}
		own := Ownership{File: img.File, Line: line, Path: resolveDocker(img.WorkDir, target), Recursive: recursive}
		if toks[0] == "chown" {
			own.User = userName(rest[0])
		} else {
			own.Mode = rest[0]
		}
		img.Owners = append(img.Owners, own)
	}
}

// symbolicRemoval reports a chmod mode that starts with '-', as in
// `chmod -w file`, which is a mode and not a flag.
func symbolicRemoval(a string) bool {
	return len(a) > 1 && a[0] == '-' && strings.Trim(a[1:], "rwxXst") == ""
}

// cronEcho returns the quoted text an echo redirects into /etc/cron.d/.
func cronEcho(text string) (string, bool) {
	rest := strings.TrimSpace(strings.TrimPrefix(text, "echo"))
	if rest == "" || (rest[0] != '"' && rest[0] != '\'') {
		return "", false
	}
	end := strings.IndexByte(rest[1:], rest[0])
	if end < 0 {
		return "", false
	}
	target := strings.TrimLeft(strings.TrimSpace(rest[end+2:]), ">")
	fields := fieldsQuoted(target)
	if !strings.HasPrefix(strings.TrimSpace(rest[end+2:]), ">") || len(fields) == 0 || !strings.HasPrefix(unquote(fields[0]), "/etc/cron.d/") {
		return "", false
	}
	return rest[1 : 1+end], true
}

func literalOperand(s string) bool {
	u := unquote(s)
	return u != "" && !strings.ContainsAny(u, "*?[$")
}

// escapes reports a COPY source that leaves the build context.
func escapes(src string) bool {
	clean := path.Clean(src)
	return clean == ".." || strings.HasPrefix(clean, "../")
}

func resolveDocker(work, p string) string {
	p = unquote(p)
	if p == "" {
		return work
	}
	if !path.IsAbs(p) {
		p = path.Join(work, p)
	}
	return path.Clean(p)
}

func userName(s string) string {
	s = unquote(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

func envName(dst string) bool {
	switch path.Base(dst) {
	case ".env", ".env.local", ".env.prod", ".env.prod.local":
		return true
	}
	return false
}

func serverConfDir(dst string) bool {
	for _, pre := range []string{"/etc/apache2/", "/etc/httpd/", "/usr/local/apache2/conf/", "/etc/nginx/"} {
		if strings.HasPrefix(dst, pre) {
			return true
		}
	}
	return false
}

// GroupOrOtherWrite reports whether a chmod mode gives group or other write.
// It reads an octal mode and the symbolic clauses that add or set w.
func GroupOrOtherWrite(mode string) bool {
	if mode == "" {
		return false
	}
	if strings.Trim(mode, "01234567") == "" {
		var n int
		for _, c := range mode {
			n = n*8 + int(c-'0')
		}
		return n&0o022 != 0
	}
	for _, clause := range strings.Split(mode, ",") {
		i := strings.IndexAny(clause, "+=-")
		if i < 0 || clause[i] == '-' || !strings.Contains(clause[i+1:], "w") {
			continue
		}
		if who := clause[:i]; who == "" || strings.ContainsAny(who, "goa") {
			return true
		}
	}
	return false
}
