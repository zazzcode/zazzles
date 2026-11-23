package langphp

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// plainWherePart matches one WHERE comparison of a column with a dynamic
// statement piece, written as \x00index\x00.
var plainWherePart = regexp.MustCompile("(?i)\\w`?\\s*=\\s*['\"]?\x00(\\d+)\x00")

func (f *phpFlow) notePlainSQL(n *sitter.Node, text phpValue) {
	if f.symfony != nil || n == nil {
		return
	}
	constant, ok := phpSQLText(text)
	if !ok {
		f.notePlainSelected(n, text)
		return
	}
	up := strings.ToUpper(constant)
	op := ""
	switch {
	case strings.Contains(up, "INSERT"):
		op = "create"
	case strings.Contains(up, "UPDATE"):
		op = "update"
	case strings.Contains(up, "DELETE"):
		op = "delete"
	default:
		return
	}
	sink := f.module.evidence(analysis.AuthorizationKind, n)
	f.notePlainOperation(n, analysis.StateChange{Operation: op, Span: sink.Span})
}

// notePlainSelected records a plain-PHP UPDATE or DELETE whose WHERE clause
// compares a column with a request value: the request selects the row. A
// WHERE part read from the session is recorded as a query-scope guard. The
// scanner does not decide that a guard is enough.
func (f *phpFlow) notePlainSelected(n *sitter.Node, text phpValue) {
	if len(text.pieces) == 0 {
		return
	}
	var b strings.Builder
	for i, p := range text.pieces {
		if p.dynamic {
			fmt.Fprintf(&b, "\x00%d\x00", i)
		} else {
			b.WriteString(p.text)
		}
	}
	op, table, where, ok := sqlWriteWhere(b.String())
	if !ok {
		return
	}
	var selecting []phpDep
	scoped := false
	for _, part := range plainWherePart.FindAllStringSubmatch(where, -1) {
		i, err := strconv.Atoi(part[1])
		if err != nil || i >= len(text.pieces) {
			continue
		}
		request, session := plainPartDeps(text.pieces[i].val)
		if session {
			scoped = true
			continue
		}
		selecting = append(selecting, request...)
	}
	if len(selecting) == 0 {
		return
	}
	sub := &phpAuthz{provenance: analysis.SubjectRequestSelected, class: "table:" + strings.ToLower(table), selecting: selecting}
	if scoped {
		sub.queryScope, sub.finder = true, n
	}
	sink := f.module.evidence(analysis.AuthorizationKind, n)
	change := analysis.StateChange{Operation: op, Span: sink.Span}
	f.addAuthzChange(change)
	f.emitAuthz(sink, n, sub, change, []string{analysis.FacetObjectLevel}, nil, nil)
}

// plainPartDeps returns the request dependencies of one statement part that
// did not pass through storage, and whether the part reads the session.
func plainPartDeps(v phpValue) (request []phpDep, session bool) {
	phpEachDep(v, func(d phpDep) {
		switch {
		case d.container == "_SESSION" || strings.HasPrefix(d.dep.StorageKey, "php-session:"):
			session = true
		case d.dep.Source.Kind == "input_source" && d.dep.StorageKey == "":
			request = append(request, d)
		}
	})
	return request, session
}

func (f *phpFlow) notePlainOperation(n *sitter.Node, change analysis.StateChange) {
	guards := f.dominatingGuards(n, nil)
	if len(guards) != 1 || guards[0].Kind != analysis.GuardAddress {
		return
	}
	f.addAuthzChange(change)
	f.emitAuthz(f.module.evidence(analysis.AuthorizationKind, n), n, &phpAuthz{}, change, nil, nil, nil)
}
