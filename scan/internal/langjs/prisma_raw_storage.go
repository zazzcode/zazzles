package langjs

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"regexp"
	"strconv"
	"strings"
)

var sqlUpdateSet = regexp.MustCompile(`(?is)^\s*update\s+([a-z_][a-z0-9_]*)\s+set\s+(.+?)(?:\s+where\s+|$)`)

// prismaRawStorage links explicit raw SQL column writes to Prisma's declared
// physical schema. Literal table/column identity is mandatory; joins and
// computed identifiers never acquire a storage link.
func (f *flow) prismaRawStorage(call, args *sitter.Node) {
	if f.set == nil || args == nil || args.NamedChildCount() == 0 {
		return
	}
	fn := call.ChildByFieldName("function")
	if fn == nil || !(strings.HasSuffix(fn.Utf8Text(f.module.src), ".$queryRawUnsafe") || strings.HasSuffix(fn.Utf8Text(f.module.src), ".$executeRawUnsafe")) {
		return
	}
	contract, _, _, ok := f.set.sqlLibraryCall(f.module, call)
	if !ok || contract != analysispacks.PrismaRawContract {
		return
	}
	arg := unwrapTS(args.NamedChild(0))
	if arg.Kind() == "identifier" {
		arg = unwrapTS(localInitializer(f.module, call, arg.Utf8Text(f.module.src)))
		if arg == nil {
			return
		}
	}
	text, subs, ok := pgliteSQLText(f.module, arg)
	if !ok {
		return
	}
	table := ""
	var columns, items []string
	if match := sqlInsertInto.FindStringSubmatch(text); match != nil {
		table = match[1]
		columns = splitSQLList(match[2])
		items = splitSQLList(match[3])
	} else if match := sqlUpdateSet.FindStringSubmatch(text); match != nil {
		table = match[1]
		for _, pair := range splitSQLList(match[2]) {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) != 2 {
				return
			}
			columns = append(columns, strings.TrimSpace(parts[0]))
			items = append(items, parts[1])
		}
	}
	if table == "" || len(columns) != len(items) {
		return
	}
	schema := f.set.prismaSchemaFields(f.module.file)
	if f.set.storageWrites == nil {
		f.set.storageWrites = map[string][]storageWrite{}
	}
	for i, column := range columns {
		physical := "sql:" + strings.ToLower(table) + "." + strings.ToLower(strings.Trim(strings.TrimSpace(column), `"`))
		key := ""
		for model, fields := range schema {
			for name, stored := range fields {
				if stored == physical {
					if key != "" && key != model+"."+name {
						return
					}
					key = model + "." + name
				}
			}
		}
		if key == "" {
			continue
		}
		// Only a complete substitution or parameter is one column value. Mixed SQL
		// expressions remain unresolved rather than borrowing another field's origin.
		item := strings.Trim(strings.TrimSpace(items[i]), "'")
		var operand *sitter.Node
		for j, sub := range subs {
			if item == "\x00"+strconv.Itoa(j)+"\x00" {
				operand = sub
			}
		}
		if operand == nil && strings.HasPrefix(item, "$") {
			if index, err := strconv.Atoi(item[1:]); err == nil && index > 0 && uint(index) < args.NamedChildCount() {
				operand = args.NamedChild(uint(index))
			}
		}
		if operand == nil {
			continue
		}
		v := f.eval(operand)
		if len(v.deps) == 0 {
			continue
		}
		f.set.storageWrites[key] = append(f.set.storageWrites[key], storageWrite{f.entry.ID, v, f.module.evidence("storage_write", call)})
	}
}
