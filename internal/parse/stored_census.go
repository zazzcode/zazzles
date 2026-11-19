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
)

// CensusStoredWrites is the language-neutral write census (W3a) for records
// whose stored origin is unresolved and whose adapter attached no write set:
// PHP and Python SQL tables (php-sql:, python-sql:), PHP session keys
// (php-session:) and Prisma models read through an application's own API.
// For each read key it lists every write statement found in the scanned
// snapshot, whether its values are literals, the schema when one is in
// scanned source, and whether the store is closed. It is evidence only: no
// dependency, identity or status changes. Files are read from the report root
// and used only when their hash matches the scanned snapshot.
func CensusStoredWrites(report *analysis.AnalysisReport) {
	var c *storeCensus
	for i := range report.Uses {
		u := &report.Uses[i]
		if u.StoredOrigin != nil && len(u.StoredOrigin.Stores) > 0 || !storedOriginBlocked(*u) {
			continue
		}
		if c == nil {
			c = newStoreCensus(report)
		}
		var stores []analysis.StoredWriteSet
		seen := map[string]bool{}
		for _, d := range u.Dependencies {
			key := d.StorageKey
			if key == "" {
				key = prismaReadKey(d)
			}
			if key == "" || strings.HasPrefix(key, "file:") || seen[key] {
				continue
			}
			seen[key] = true
			if set, ok := c.writeSet(key); ok {
				stores = append(stores, set)
			}
		}
		if len(stores) > 0 {
			u.StoredOrigin = &analysis.StoredOriginFacts{Stores: stores}
		}
	}
}

func storedOriginBlocked(u analysis.CandidateUse) bool {
	if u.Completeness == nil {
		return false
	}
	for _, g := range u.Completeness.Blockers {
		if g.Kind == "storage_origin_unresolved" {
			return true
		}
	}
	return false
}

var prismaRead = regexp.MustCompile(`\bprisma\.(\w+)\.(?:find\w*|aggregate|count|groupBy)\s*\(`)

// prismaReadKey names the Prisma model a storage read reads, for a read that
// carries no storage key (an own-API row read).
func prismaReadKey(d analysis.Dependency) string {
	for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
		if e.Kind != "storage_read" {
			continue
		}
		if m := prismaRead.FindStringSubmatch(e.Text); m != nil {
			return "prisma:" + m[1]
		}
	}
	return ""
}

// censusFile is one scanned file whose bytes match the snapshot.
type censusFile struct {
	path, sha string
	src       []byte
}

type storeCensus struct {
	files []censusFile
	sets  map[string]analysis.StoredWriteSet
}

func newStoreCensus(report *analysis.AnalysisReport) *storeCensus {
	c := &storeCensus{sets: map[string]analysis.StoredWriteSet{}}
	seen := map[string]bool{}
	for _, f := range report.Files {
		path := f.Span.File
		if seen[path] || report.Root == "" {
			continue
		}
		seen[path] = true
		src, err := os.ReadFile(filepath.Join(report.Root, path))
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(src)) != f.SHA256 {
			continue // not the scanned snapshot
		}
		c.files = append(c.files, censusFile{path: path, sha: f.SHA256, src: src})
	}
	sort.Slice(c.files, func(i, j int) bool { return c.files[i].path < c.files[j].path })
	return c
}

var (
	censusCreateTable = `(?is)\bcreate\s+table\s+(?:if\s+not\s+exists\s+)?["'\x60\[]?%s["'\x60\]]?[\s(]`
	censusWriteTable  = `(?is)\b(?:insert\s+(?:or\s+\w+\s+)?into|replace\s+into|update)\s+["'\x60\[]?%s["'\x60\]]?[\s(]`
	// censusNonLiteral marks a write whose values are not all source
	// literals: interpolation, a placeholder, concatenation or formatting.
	censusNonLiteral = regexp.MustCompile(`\$\w|\{\$|\?|%s|%\(|(?:^|[\s(,=])[:@]\w+|["']\s*\.\s*\$|\.\s*["']|\.format\(|\bf["']|["']\s*\+|\+\s*["']`)
	sessionWrite     = `\$_SESSION\s*\[\s*['"]%s['"]\s*\](?:\s*\[[^\]]*\])*\s*=[^=]`
	sessionLiteral   = regexp.MustCompile(`^\s*(?:'[^'$]*'|"[^"$]*"|-?\d+(?:\.\d+)?|true|false|null|array\(\s*\)|\[\s*\])\s*;`)
	prismaWrite      = `\bprisma\.%s\.(?:create|createMany|update|updateMany|upsert)\s*\(`
)

// writeSet returns the census for one key, or false for a key this census
// does not own.
func (c *storeCensus) writeSet(key string) (analysis.StoredWriteSet, bool) {
	if set, ok := c.sets[key]; ok {
		return set, true
	}
	prefix, rest, _ := strings.Cut(key, ":")
	set := analysis.StoredWriteSet{Key: key, Writes: []analysis.StoredWrite{}, ClosedStore: "open"}
	switch prefix {
	case "php-sql", "python-sql":
		ext := ".php"
		if prefix == "python-sql" {
			ext = ".py"
		}
		table, _, _ := strings.Cut(rest, ".")
		if table == "" {
			return set, false
		}
		name := regexp.QuoteMeta(table)
		write := regexp.MustCompile(fmt.Sprintf(censusWriteTable, name))
		create := regexp.MustCompile(fmt.Sprintf(censusCreateTable, name))
		for _, f := range c.files {
			if !strings.HasSuffix(f.path, ext) {
				continue
			}
			for _, loc := range write.FindAllIndex(f.src, -1) {
				e, text := statementEvidence(f, loc[0], ';')
				if prefix == "python-sql" {
					e, text = lineStatement(f, loc[0])
				}
				set.Writes = append(set.Writes, analysis.StoredWrite{Evidence: e, Literal: !censusNonLiteral.MatchString(text)})
			}
			if set.Schema == nil {
				if loc := create.FindIndex(f.src); loc != nil {
					e, _ := statementEvidence(f, loc[0], ';')
					e.Kind = "storage_schema"
					set.Schema = &e
				}
			}
		}
		if set.Schema != nil {
			// The schema is in source, but the database is an external
			// server that other writers may reach.
			set.ClosedStore = "unknown"
		}
	case "php-session":
		write := regexp.MustCompile(fmt.Sprintf(sessionWrite, regexp.QuoteMeta(rest)))
		for _, f := range c.files {
			if !strings.HasSuffix(f.path, ".php") {
				continue
			}
			for _, loc := range write.FindAllIndex(f.src, -1) {
				e, _ := statementEvidence(f, loc[0], ';')
				rhs := f.src[loc[1]-1:]
				set.Writes = append(set.Writes, analysis.StoredWrite{Evidence: e, Literal: sessionLiteral.Match(rhs)})
			}
		}
		// A server-held session has no client writer, but its writers are not
		// proven complete (included files, frameworks), so it is not closed.
		set.ClosedStore = "unknown"
	case "prisma":
		write := regexp.MustCompile(fmt.Sprintf(prismaWrite, regexp.QuoteMeta(rest)))
		for _, f := range c.files {
			if !strings.HasSuffix(f.path, ".ts") && !strings.HasSuffix(f.path, ".tsx") && !strings.HasSuffix(f.path, ".js") && !strings.HasSuffix(f.path, ".mjs") {
				continue
			}
			for _, loc := range write.FindAllIndex(f.src, -1) {
				e, text := callEvidence(f, loc[0], loc[1]-1)
				set.Writes = append(set.Writes, analysis.StoredWrite{Evidence: e, Literal: literalObject(text)})
			}
		}
	default:
		return set, false
	}
	c.sets[key] = set
	return set, true
}

// statementEvidence covers from the line holding start to the line holding
// the next end byte (bounded), as a storage_write item of the snapshot.
func statementEvidence(f censusFile, start int, end byte) (analysis.Evidence, string) {
	lineStart := start
	for lineStart > 0 && f.src[lineStart-1] != '\n' {
		lineStart--
	}
	stop := start
	for lines := 0; stop < len(f.src) && f.src[stop] != end && lines < 20; stop++ {
		if f.src[stop] == '\n' {
			lines++
		}
	}
	if stop < len(f.src) {
		stop++
	}
	return spanEvidence(f, lineStart, stop), string(f.src[start:stop])
}

// lineStatement covers the line holding start through the line where the
// brackets open on that line close: one Python statement.
func lineStatement(f censusFile, start int) (analysis.Evidence, string) {
	lineStart := start
	for lineStart > 0 && f.src[lineStart-1] != '\n' {
		lineStart--
	}
	depth, stop := 0, lineStart
	for ; stop < len(f.src); stop++ {
		switch f.src[stop] {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
		if f.src[stop] == '\n' && depth <= 0 {
			break
		}
	}
	return spanEvidence(f, lineStart, stop), string(f.src[start:stop])
}

// callEvidence covers a call from its start to the balanced closing paren.
func callEvidence(f censusFile, start, open int) (analysis.Evidence, string) {
	depth, stop := 0, open
	for ; stop < len(f.src); stop++ {
		switch f.src[stop] {
		case '(':
			depth++
		case ')':
			depth--
		}
		if depth == 0 {
			stop++
			break
		}
	}
	return spanEvidence(f, start, stop), string(f.src[open:stop])
}

func spanEvidence(f censusFile, start, end int) analysis.Evidence {
	line := func(at int) int { return strings.Count(string(f.src[:at]), "\n") + 1 }
	endLine := line(end)
	if end > start && f.src[end-1] == '\n' {
		endLine--
	}
	return analysis.Evidence{Kind: "storage_write", Text: strings.TrimSpace(string(f.src[start:end])), SHA256: f.sha,
		Span: analysis.Span{File: f.path, StartLine: line(start), EndLine: endLine, StartByte: start, EndByte: end}}
}

var (
	quoted     = regexp.MustCompile("'(?:[^'\\\\]|\\\\.)*'|\"(?:[^\"\\\\]|\\\\.)*\"|`[^`$]*`")
	objectKey  = regexp.MustCompile(`\b\w+\s*:`)
	literalTok = regexp.MustCompile(`\b(?:true|false|null|undefined|\d+(?:\.\d+)?)\b`)
	identifier = regexp.MustCompile(`[A-Za-z_$][\w$]*`)
)

// literalObject reports call arguments made only of literal values: after
// strings, numbers, booleans and object keys are removed, no identifier
// remains.
func literalObject(args string) bool {
	s := quoted.ReplaceAllString(args, "''")
	s = objectKey.ReplaceAllString(s, ":")
	s = literalTok.ReplaceAllString(s, "0")
	return !identifier.MatchString(s)
}
