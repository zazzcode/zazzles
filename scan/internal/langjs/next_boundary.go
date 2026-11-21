package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"path"
	"regexp"
	"strings"
)

type nextBoundary struct {
	kind     string
	entry    analysis.EntryPoint
	evidence analysis.Evidence
	value    value
}

func (f *flow) noteNextBoundary(kind string, n *sitter.Node, v value) {
	if f.set == nil || f.set.next == nil || f.web == nil {
		return
	}
	f.set.next.boundaries = append(f.set.next.boundaries, nextBoundary{kind, f.entry, f.module.evidence("browser_boundary", n), v})
}

func (s *moduleSet) practiceBoundaries(ps *practiceSet) {
	for _, b := range s.next.boundaries {
		if b.kind == "action_write" && len(b.value.deps) > 0 {
			if !practiceValueValidated(b.value) {
				ps.add("NX-BP-09", "Unvalidated public Server Action write", "review", "Server Action arguments reach a data write without established validation of every request-derived value; authorization is a separate boundary", b.entry.Name, b.evidence)
			}
		}
		if b.kind == "action_return" || b.kind == "client_props" {
			if s.sensitiveBrowserValue(b.value) {
				ps.add("NX-BP-18", "Sensitive fields cross the browser boundary", "review", "sensitive-named fields or schema-established sensitive row columns reach "+b.kind, b.entry.Name, b.evidence)
			}
		}
	}
}

func practiceValueValidated(v value) bool {
	for _, field := range v.fields {
		if !practiceValueValidated(field) {
			return false
		}
	}
	for _, d := range v.deps {
		validated := false
		for _, transfer := range d.Transfers {
			validated = validated || transfer.Kind == "validated_parse"
		}
		if !validated {
			return false
		}
	}
	return true
}

var prismaModelBlock = regexp.MustCompile(`(?s)\bmodel\s+(\w+)\s*\{([^}]+)\}`)
var prismaTableMap = regexp.MustCompile(`@@map\(\s*"([^"]+)"\s*\)`)
var prismaDatasource = regexp.MustCompile(`(?s)datasource\s+\w+\s*\{[^}]*\bprovider\s*=\s*"([^"]+)"`)
var prismaColumnMap = regexp.MustCompile(`@map\(\s*"([^"]+)"\s*\)`)

// prismaSchemaFields returns storage keys established by a literal Prisma
// schema. It never pluralizes or guesses a physical table name.
func (s *moduleSet) prismaSchemaFields(file string) map[string]map[string]string {
	start := path.Dir(file)
	if s.prismaSchemas == nil {
		s.prismaSchemas = map[string]map[string]map[string]string{}
	}
	if cached, ok := s.prismaSchemas[start]; ok {
		return cached
	}
	result := map[string]map[string]string{}
	defer func() { s.prismaSchemas[start] = result }()
	for dir := path.Dir(file); ; dir = path.Dir(dir) {
		if dir != start {
			if cached, ok := s.prismaSchemas[dir]; ok {
				result = cached
				return result
			}
		}
		schema, ok := s.readBounded(joinDir(dir, "prisma/schema.prisma"), 2<<20)
		if ok {
			folding := false
			if provider := prismaDatasource.FindStringSubmatch(schema.Text); provider != nil {
				folding = provider[1] == "sqlite"
			}
			for _, block := range prismaModelBlock.FindAllStringSubmatch(schema.Text, -1) {
				model, body := block[1], block[2]
				table := model
				if match := prismaTableMap.FindStringSubmatch(body); match != nil {
					table = match[1]
				}
				fields := map[string]string{}
				for _, line := range strings.Split(body, "\n") {
					parts := strings.Fields(line)
					if len(parts) < 2 || strings.HasPrefix(parts[0], "@") || strings.HasPrefix(parts[0], "//") {
						continue
					}
					column := parts[0]
					if match := prismaColumnMap.FindStringSubmatch(line); match != nil {
						column = match[1]
					}
					physical := ""
					// Quoted mixed-case Prisma identifiers are not the same as unquoted SQL
					// identifiers on a case-sensitive dialect. SQLite is source-declared here.
					if folding || table == strings.ToLower(table) && column == strings.ToLower(column) {
						physical = "sql:" + strings.ToLower(table) + "." + strings.ToLower(column)
					}
					fields[parts[0]] = physical
				}
				result["prisma:"+strings.ToLower(model[:1])+model[1:]] = fields
			}
			s.prismaSchemas[dir] = result
			break
		}
		if dir == "." || dir == "" {
			break
		}
	}
	return result
}

func (s *moduleSet) sensitiveBrowserValue(v value) bool {
	for key, field := range v.fields {
		if secretName.MatchString(key) || strings.EqualFold(key, "email") || s.sensitiveBrowserValue(field) {
			return true
		}
	}
	if v.read == nil || !strings.HasPrefix(v.model, "prisma:") {
		return false
	}
	fields := s.prismaSchemaFields(v.read.Span.File)[v.model]
	m := s.modules[v.read.Span.File]
	var selectNode *sitter.Node
	if m != nil {
		if call := parse.NodeAt(m.tree.RootNode(), v.read.Span.StartByte, v.read.Span.EndByte); call != nil {
			if args := call.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 0 {
				selectNode = property(args.NamedChild(0), "select", m.src)
			}
		}
	}
	for name := range fields {
		if !secretName.MatchString(name) && !strings.EqualFold(name, "email") {
			continue
		}
		if selectNode != nil {
			selected := property(selectNode, name, m.src)
			if selected == nil || selected.Utf8Text(m.src) != "true" {
				continue
			}
		}
		return true
	}
	return false
}
