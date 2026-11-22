// Package deployconf reads allow-listed deployment files as text.
// It does not execute anything and does not expand variables.
package deployconf

import (
	"strings"
	"unicode"
)

// MaxFile is the per-file read limit.
const MaxFile = 256 << 10

// Directive is one parsed directive and the scope it was written in.
type Directive struct {
	File      string
	Line      int
	Name      string
	Values    []string
	Scope     string
	Effective []string
}

// Gap is a file the reader could not use.
type Gap struct {
	Kind, Detail, File string
	Line               int
}

// Ownership is a chown, chmod or COPY --chown that changes a path.
type Ownership struct {
	File, User, Path, Mode string
	Line                   int
	Recursive              bool
}

// ScheduleLine is one cron job.
type ScheduleLine struct {
	File, User, Command string
	Line                int
	System              bool
}

// EnvPlacement is a COPY/ADD that puts a project file at an environment name.
type EnvPlacement struct {
	Src, Dst string
	Line     int
}

// DockerImage is the literal mapping and the instructions branch 4 reads.
type DockerImage struct {
	PathMap     map[string]string
	Owners      []Ownership
	Schedules   []ScheduleLine
	Modules     []Directive
	Installed   []string
	EnvFiles    []EnvPlacement
	User        string
	WorkDir     string
	CronInstall []CronInstall
	Gaps        []Gap
}

// CronInstall is a `crontab <file>` instruction and the user in force there.
type CronInstall struct {
	File, User, Path string
	Line             int
}

func unread(file string) []Gap {
	return []Gap{{Kind: "config_file_unread", Detail: "file exceeds 256 KiB or is unreadable", File: file, Line: 1}}
}

func tooBig(src []byte) bool { return len(src) > MaxFile }

// logicalLines joins a trailing backslash to the next physical line.
// Each returned string keeps its starting physical line.
func logicalLines(src []byte) []struct {
	text string
	line int
	phys map[int]int // byte offset in text -> physical line
} {
	raw := strings.Split(string(src), "\n")
	var out []struct {
		text string
		line int
		phys map[int]int
	}
	for i := 0; i < len(raw); i++ {
		start := i + 1
		var b strings.Builder
		phys := map[int]int{}
		for {
			piece := raw[i]
			cont := strings.HasSuffix(piece, "\\")
			if cont {
				piece = strings.TrimSuffix(piece, "\\")
			}
			for _, r := range piece {
				phys[b.Len()] = i + 1
				b.WriteRune(r)
			}
			if !cont || i+1 >= len(raw) {
				break
			}
			phys[b.Len()] = i + 2
			b.WriteByte(' ')
			i++
		}
		out = append(out, struct {
			text string
			line int
			phys map[int]int
		}{b.String(), start, phys})
	}
	return out
}

func lineAt(phys map[int]int, text, needle string, fallback int) int {
	idx := strings.Index(strings.ToLower(text), strings.ToLower(needle))
	if idx < 0 || phys == nil {
		return fallback
	}
	if n, ok := phys[idx]; ok {
		return n
	}
	bestOff, best := -1, fallback
	for off, line := range phys {
		if off <= idx && off >= bestOff {
			bestOff, best = off, line
		}
	}
	return best
}

func stripComment(line string) string {
	var b strings.Builder
	quote := byte(0)
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if c == '#' || c == ';' {
			break
		}
		b.WriteByte(c)
	}
	return strings.TrimSpace(b.String())
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func fieldsQuoted(line string) []string {
	var out []string
	var b strings.Builder
	quote := byte(0)
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			b.WriteByte(c)
			continue
		}
		if unicode.IsSpace(rune(c)) {
			flush()
			continue
		}
		b.WriteByte(c)
	}
	flush()
	return out
}

// Apache reads Options, DocumentRoot, RemoteIPHeader and RemoteIPTrustedProxy.
func Apache(file string, src []byte) ([]Directive, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	type frame struct {
		scope   string
		options []string
	}
	stack := []frame{{}}
	var out []Directive
	for _, row := range logicalLines(src) {
		text := stripComment(row.text)
		if text == "" {
			continue
		}
		low := strings.ToLower(text)
		switch {
		case strings.HasPrefix(low, "<directory"), strings.HasPrefix(low, "<virtualhost"):
			path := between(text)
			stack = append(stack, frame{scope: path, options: append([]string{}, stack[len(stack)-1].options...)})
		case strings.HasPrefix(low, "</directory"), strings.HasPrefix(low, "</virtualhost"):
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		default:
			toks := fieldsQuoted(text)
			if len(toks) == 0 {
				continue
			}
			name := toks[0]
			switch strings.ToLower(name) {
			case "options":
				parent := []string{}
				if len(stack) > 1 {
					parent = stack[len(stack)-2].options
				}
				effective := applyOptions(parent, toks[1:])
				stack[len(stack)-1].options = effective
				scope := stack[len(stack)-1].scope
				if scope == "" && strings.HasSuffix(file, ".htaccess") {
					if i := strings.LastIndex(file, "/"); i > 0 {
						scope = file[:i]
					}
				}
				out = append(out, Directive{
					File: file, Line: row.line, Name: "Options", Values: cleanValues(toks[1:]),
					Scope: scope, Effective: append([]string{}, effective...),
				})
			case "documentroot", "remoteipheader", "remoteiptrustedproxy":
				val := ""
				if len(toks) > 1 {
					val = unquote(toks[1])
				}
				out = append(out, Directive{
					File: file, Line: row.line, Name: canonicalApache(name), Values: []string{val},
					Scope: stack[len(stack)-1].scope,
				})
			}
		}
	}
	return out, nil
}

func canonicalApache(name string) string {
	switch strings.ToLower(name) {
	case "documentroot":
		return "DocumentRoot"
	case "remoteipheader":
		return "RemoteIPHeader"
	case "remoteiptrustedproxy":
		return "RemoteIPTrustedProxy"
	}
	return name
}

func between(text string) string {
	i := strings.IndexByte(text, ' ')
	j := strings.LastIndexByte(text, '>')
	if i < 0 || j < i {
		return ""
	}
	return unquote(strings.TrimSpace(text[i:j]))
}

func cleanValues(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = unquote(v)
	}
	return out
}

// applyOptions implements Apache's relative and replacement forms.
// A list whose every token has + or - edits the inherited set. Any bare
// token replaces it. Options None clears the set.
func applyOptions(inherited, tokens []string) []string {
	if len(tokens) == 1 && strings.EqualFold(unquote(tokens[0]), "none") {
		return nil
	}
	relative := true
	for _, tok := range tokens {
		t := unquote(tok)
		if t == "" || (t[0] != '+' && t[0] != '-') {
			relative = false
			break
		}
	}
	set := map[string]bool{}
	var order []string
	add := func(name string) {
		if !set[name] {
			set[name] = true
			order = append(order, name)
		}
	}
	del := func(name string) {
		if set[name] {
			set[name] = false
		}
	}
	if relative {
		for _, name := range inherited {
			add(name)
		}
	}
	for _, tok := range tokens {
		t := unquote(tok)
		switch {
		case strings.HasPrefix(t, "+"):
			add(t[1:])
		case strings.HasPrefix(t, "-"):
			del(t[1:])
		default:
			add(t)
		}
	}
	var out []string
	for _, name := range order {
		if set[name] {
			out = append(out, name)
		}
	}
	return out
}

// Nginx reads autoindex, real_ip_header and set_real_ip_from with the
// enclosing location, if any.
func Nginx(file string, src []byte) ([]Directive, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	var scope string
	var out []Directive
	for _, row := range logicalLines(src) {
		text := stripComment(row.text)
		if text == "" {
			continue
		}
		low := strings.ToLower(text)
		if strings.HasPrefix(low, "location") && strings.Contains(text, "{") {
			head, tail, _ := strings.Cut(text, "{")
			scope = strings.TrimSpace(head[len("location"):])
			text = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(tail), "}"))
			if text == "" {
				continue
			}
			low = strings.ToLower(text)
		}
		if text == "}" {
			scope = ""
			continue
		}
		toks := fieldsQuoted(strings.TrimSuffix(text, ";"))
		if len(toks) == 0 {
			continue
		}
		name := strings.ToLower(toks[0])
		switch name {
		case "autoindex", "real_ip_header", "set_real_ip_from":
			val := ""
			if len(toks) > 1 {
				val = unquote(strings.TrimSuffix(toks[1], ";"))
			}
			sc := ""
			if scope != "" {
				sc = "location " + strings.TrimSpace(scope)
			}
			out = append(out, Directive{File: file, Line: row.line, Name: name, Values: []string{val}, Scope: sc})
		}
	}
	return out, nil
}

// Dockerfile reads literal WORKDIR, COPY, ADD, USER, RUN, a2enmod and
// cron echoes. An operand with a build argument or a glob is unresolved.
func Dockerfile(file string, src []byte) DockerImage {
	img := DockerImage{PathMap: map[string]string{}, User: "root", WorkDir: "/"}
	if tooBig(src) {
		img.Gaps = unread(file)
		return img
	}
	for _, row := range logicalLines(src) {
		text := stripComment(row.text)
		if text == "" {
			continue
		}
		toks := fieldsQuoted(text)
		if len(toks) == 0 {
			continue
		}
		op := strings.ToUpper(toks[0])
		switch op {
		case "WORKDIR":
			if len(toks) > 1 && literalOperand(toks[1]) {
				img.WorkDir = resolveDocker(img.WorkDir, unquote(toks[1]))
			} else if len(toks) > 1 {
				img.Gaps = append(img.Gaps, Gap{Kind: "deploy_mapping_unresolved", Detail: "WORKDIR operand is not literal", File: file, Line: row.line})
			}
		case "USER":
			if len(toks) > 1 && literalOperand(toks[1]) {
				img.User = userName(unquote(toks[1]))
			}
		case "COPY", "ADD":
			img.copy(file, row.line, row.text, op, toks)
		case "RUN":
			img.run(file, row.line, text, row.phys)
		}
	}
	return img
}

func (img *DockerImage) copy(file string, line int, raw, op string, toks []string) {
	args := toks[1:]
	chown := ""
	var paths []string
	for _, a := range args {
		u := unquote(a)
		if strings.HasPrefix(strings.ToLower(u), "--chown=") {
			chown = userName(strings.TrimPrefix(u[len("--chown="):], ""))
			continue
		}
		if strings.HasPrefix(u, "--") {
			continue
		}
		paths = append(paths, u)
	}
	if op == "ADD" && len(paths) > 0 && strings.Contains(paths[0], "://") {
		return
	}
	if len(paths) < 2 {
		return
	}
	dst := paths[len(paths)-1]
	srcs := paths[:len(paths)-1]
	dstAbs := resolveDocker(img.WorkDir, dst)
	// COPY of one file onto an existing directory keeps the source base name.
	if len(srcs) == 1 && srcs[0] != "." && !strings.HasSuffix(srcs[0], "/") {
		if _, ok := img.PathMap[dstAbs]; ok || dstAbs == img.WorkDir {
			base := srcs[0]
			if i := strings.LastIndex(base, "/"); i >= 0 {
				base = base[i+1:]
			}
			dstAbs = strings.TrimRight(dstAbs, "/") + "/" + base
		}
	}
	unresolved := false
	for _, src := range srcs {
		if !literalOperand(src) {
			unresolved = true
			continue
		}
		img.PathMap[dstAbs] = src
		if envName(dstAbs) {
			img.EnvFiles = append(img.EnvFiles, EnvPlacement{Src: src, Dst: dstAbs, Line: line})
		}
	}
	if unresolved {
		img.Gaps = append(img.Gaps, Gap{Kind: "deploy_mapping_unresolved", Detail: "COPY or ADD operand is not literal", File: file, Line: line})
	}
	if chown != "" {
		img.Owners = append(img.Owners, Ownership{File: file, Line: line, User: chown, Path: dstAbs})
	}
	if serverConfDir(dstAbs) {
		img.Installed = append(img.Installed, dstAbs)
		for _, src := range srcs {
			if literalOperand(src) {
				img.Installed = append(img.Installed, src)
			}
		}
	}
}

func (img *DockerImage) run(file string, line int, text string, phys map[int]int) {
	// a2enmod tokens
	if i := strings.Index(text, "a2enmod"); i >= 0 {
		rest := text[i+len("a2enmod"):]
		if cut := strings.Index(rest, "&&"); cut >= 0 {
			rest = rest[:cut]
		}
		for _, tok := range fieldsQuoted(rest) {
			tok = unquote(tok)
			if tok == "" || strings.HasPrefix(tok, "-") {
				continue
			}
			img.Modules = append(img.Modules, Directive{File: file, Line: line, Name: "a2enmod", Values: []string{tok}})
		}
	}
	lower := strings.ToLower(text)
	if strings.Contains(lower, "chown") || strings.Contains(lower, "chmod") {
		img.own(file, line, text, phys)
	}
	if echo, path, ok := cronEcho(text); ok {
		jobs := Cron(file, []byte(echo), true)
		for i := range jobs {
			jobs[i].Line = line
			jobs[i].File = file
		}
		img.Schedules = append(img.Schedules, jobs...)
		_ = path
	}
	if path, ok := crontabInstall(text); ok {
		img.CronInstall = append(img.CronInstall, CronInstall{File: file, Line: line, User: img.User, Path: path})
	}
}

func (img *DockerImage) own(file string, line int, text string, phys map[int]int) {
	// Walk command segments split on && so each chown/chmod is its own.
	for _, seg := range strings.Split(text, "&&") {
		toks := fieldsQuoted(strings.TrimSpace(seg))
		if len(toks) > 0 && strings.EqualFold(unquote(toks[0]), "RUN") {
			toks = toks[1:]
		}
		if len(toks) == 0 {
			continue
		}
		name := strings.ToLower(unquote(toks[0]))
		if name != "chown" && name != "chmod" {
			continue
		}
		at := lineAt(phys, text, name, line)
		// physical line: search the raw joined text's original via the segment
		args := toks[1:]
		recursive := false
		var rest []string
		for _, a := range args {
			u := unquote(a)
			if u == "-R" || u == "-r" || strings.HasPrefix(u, "-R") {
				recursive = true
				continue
			}
			if strings.HasPrefix(u, "-") {
				continue
			}
			rest = append(rest, u)
		}
		if name == "chown" && len(rest) >= 2 {
			img.Owners = append(img.Owners, Ownership{
				File: file, Line: at, User: userName(rest[0]), Path: resolveDocker(img.WorkDir, rest[len(rest)-1]), Recursive: recursive,
			})
		}
		if name == "chmod" && len(rest) >= 2 {
			img.Owners = append(img.Owners, Ownership{
				File: file, Line: at, Mode: rest[0], Path: resolveDocker(img.WorkDir, rest[len(rest)-1]), Recursive: recursive,
			})
		}
	}
}

func cronEcho(text string) (body, path string, ok bool) {
	low := strings.ToLower(text)
	i := strings.Index(low, "echo")
	if i < 0 {
		return "", "", false
	}
	rest := strings.TrimSpace(text[i+len("echo"):])
	if rest == "" || (rest[0] != '"' && rest[0] != '\'') {
		return "", "", false
	}
	q := rest[0]
	end := strings.IndexByte(rest[1:], q)
	if end < 0 {
		return "", "", false
	}
	body = rest[1 : 1+end]
	tail := rest[1+end+1:]
	j := strings.Index(tail, ">")
	if j < 0 || !strings.Contains(tail[j:], "/etc/cron.d/") {
		return "", "", false
	}
	fields := fieldsQuoted(tail[j+1:])
	if len(fields) == 0 {
		return "", "", false
	}
	return body, unquote(fields[0]), true
}

func crontabInstall(text string) (string, bool) {
	for _, seg := range strings.Split(text, "&&") {
		toks := fieldsQuoted(strings.TrimSpace(seg))
		if len(toks) >= 2 && unquote(toks[0]) == "crontab" && !strings.HasPrefix(unquote(toks[1]), "-") {
			return unquote(toks[1]), true
		}
	}
	return "", false
}

func literalOperand(s string) bool {
	u := unquote(s)
	if strings.ContainsAny(u, "*?[") || strings.Contains(u, "$") {
		return false
	}
	return u != ""
}

func resolveDocker(work, p string) string {
	p = unquote(p)
	if p == "" {
		return work
	}
	if !strings.HasPrefix(p, "/") {
		if work == "/" {
			return "/" + p
		}
		return strings.TrimRight(work, "/") + "/" + p
	}
	return pathClean(p)
}

func pathClean(p string) string {
	parts := strings.Split(p, "/")
	var out []string
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if part == ".." && len(out) > 0 {
			out = out[:len(out)-1]
			continue
		}
		out = append(out, part)
	}
	return "/" + strings.Join(out, "/")
}

func userName(s string) string {
	s = unquote(s)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = s[:i]
	}
	return s
}

func envName(dst string) bool {
	base := dst[strings.LastIndex(dst, "/")+1:]
	switch base {
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

// Cron reads one crontab file. system selects the six-field form.
func Cron(file string, src []byte, system bool) []ScheduleLine {
	if tooBig(src) {
		return nil
	}
	var out []ScheduleLine
	for _, row := range logicalLines(src) {
		text := stripComment(row.text)
		if text == "" || envAssign(text) {
			continue
		}
		toks := fieldsQuoted(text)
		need := 5
		if system {
			need = 6
		}
		if len(toks) <= need {
			continue
		}
		user := ""
		cmdAt := need
		if system {
			user = unquote(toks[5])
			if strings.Contains(user, "/") {
				continue
			}
		}
		cmd := strings.TrimSpace(strings.Join(quoteStrip(toks[cmdAt:]), " "))
		out = append(out, ScheduleLine{File: file, Line: row.line, User: user, Command: cmd, System: system})
	}
	return out
}

func quoteStrip(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = unquote(s)
	}
	return out
}

func envAssign(text string) bool {
	toks := fieldsQuoted(text)
	if len(toks) == 0 {
		return false
	}
	first := unquote(toks[0])
	if strings.HasPrefix(first, "export ") {
		return false
	}
	name := first
	if i := strings.IndexByte(first, '='); i > 0 {
		name = first[:i]
	} else if len(toks) > 1 && toks[1] == "=" {
		name = first
	} else {
		return false
	}
	if name == "" {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

// PHPIni reads the directives the checks name.
func PHPIni(file string, src []byte) ([]Directive, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	var out []Directive
	for _, row := range logicalLines(src) {
		text := stripComment(row.text)
		if text == "" || !strings.Contains(text, "=") {
			continue
		}
		parts := strings.SplitN(text, "=", 2)
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		val := unquote(strings.TrimSpace(parts[1]))
		switch name {
		case "display_errors", "session.cookie_httponly", "session.cookie_secure":
			out = append(out, Directive{File: file, Line: row.line, Name: name, Values: []string{val}})
		}
	}
	return out, nil
}

// EnvKeys returns APP_ENV and APP_DEBUG only. Every other line is discarded
// before a value is stored.
func EnvKeys(file string, src []byte) (map[string]string, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	out := map[string]string{}
	for _, row := range logicalLines(src) {
		text := stripComment(row.text)
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "export ") {
			text = strings.TrimSpace(strings.TrimPrefix(text, "export "))
		}
		i := strings.IndexByte(text, '=')
		if i <= 0 {
			continue
		}
		key := strings.TrimSpace(text[:i])
		if key != "APP_ENV" && key != "APP_DEBUG" {
			continue
		}
		out[key] = unquote(strings.TrimSpace(text[i+1:]))
	}
	return out, nil
}

// Indexes reports whether an Options effective list enables listing.
func Indexes(effective []string) bool {
	for _, name := range effective {
		if name == "Indexes" {
			return true
		}
	}
	return false
}
