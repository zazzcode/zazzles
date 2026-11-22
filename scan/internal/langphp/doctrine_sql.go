package langphp

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

const (
	doctrineDBALDriver = "doctrine-dbal"
	doctrineORMDriver  = "doctrine-orm"
	doctrineConnection = `Doctrine\DBAL\Connection`
	doctrineManager    = `Doctrine\ORM\EntityManagerInterface`
)

func doctrineHandle(class string) string {
	switch strings.ToLower(class) {
	case `doctrine\dbal\connection`:
		return "doctrine_connection"
	case `doctrine\orm\entitymanagerinterface`, `doctrine\orm\entitymanager`, `doctrine\persistence\objectmanager`:
		return "doctrine_manager"
	case `doctrine\persistence\managerregistry`:
		return "doctrine_registry"
	}
	return ""
}

func (f *phpFlow) doctrineRepository(decl *phpClassDecl) bool {
	for steps := 0; decl != nil && steps <= phpClassDepth; steps++ {
		parent := firstNamedChild(firstChildOfKind(decl.node, "base_clause"))
		if parent == nil {
			return false
		}
		idx := f.set.classIndex()
		name := idx.qualify(decl.module, phpText(decl.module, parent), parent.StartByte())
		switch strings.ToLower(name) {
		case `doctrine\bundle\doctrinebundle\repository\serviceentityrepository`, `doctrine\orm\entityrepository`:
			return true
		}
		decl, _ = idx.parentOf(decl)
	}
	return false
}

func (f *phpFlow) doctrineProperty(n *sitter.Node, base phpValue, key string) (phpValue, bool) {
	if f.symfony == nil {
		return phpValue{}, false
	}
	if key == "_em" && phpVarName(f.module, phpField(n, "object")) == "this" && f.doctrineRepository(base.classDecl) {
		return f.doctrineReceiver(n, doctrineManager), true
	}
	for decl, depth := base.classDecl, 0; decl != nil && depth <= phpClassDepth; depth++ {
		if property := symfonyProperties(decl)[key]; property != nil {
			typeNode := phpField(property, "type")
			if typeNode == nil {
				return phpValue{}, false
			}
			class := f.set.classIndex().qualify(decl.module, strings.TrimPrefix(phpText(decl.module, typeNode), "?"), typeNode.StartByte())
			if doctrineHandle(class) == "doctrine_connection" {
				v := f.doctrineReceiver(n, class)
				v.evidence = append(v.evidence, decl.module.evidence("server_binding", property))
				return v, true
			}
			return phpValue{}, false
		}
		decl, _ = f.set.classIndex().parentOf(decl)
	}
	return phpValue{}, false
}

func (f *phpFlow) doctrineReceiver(n *sitter.Node, class string) phpValue {
	return phpValue{binding: doctrineHandle(class), class: class, evidence: []analysis.Evidence{f.module.evidence("sink_binding", n)}}
}

func (f *phpFlow) doctrineSQLCall(n *sitter.Node, receiver phpValue, method string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	if f.symfony == nil {
		return phpValue{}, false
	}
	method = strings.ToLower(method)
	kind := receiver.binding
	if receiver.classDecl != nil && f.doctrineRepository(receiver.classDecl) {
		// An application override is dispatched through normal PHP method flow.
		if _, fn, _, _ := f.set.classIndex().method(receiver.classDecl, method); fn != nil {
			return phpValue{}, false
		}
		kind = "doctrine_repository"
	} else if receiver.binding == "symfony_opaque" {
		kind = doctrineHandle(receiver.class)
	}
	switch kind {
	case "doctrine_connection", "doctrine_statement", "doctrine_result":
		return f.doctrineDBALCall(n, receiver, kind, method, nodes, values)
	case "doctrine_manager", "doctrine_registry", "doctrine_repository", "doctrine_builder", "doctrine_query":
		return f.doctrineORMCall(n, receiver, kind, method, nodes, values)
	}
	if receiver.class == "" && receiver.classDecl == nil && doctrineDBALConnectionOperation(method) {
		gap := f.gap("php_call_unresolved", "Doctrine-compatible operation has no resolved receiver", n)
		f.gaps = append(f.gaps, gap)
		v := phpTransfer(phpProtect(sliceFrom(values, 0), "unknown"), f.module.evidence("call_argument_dependency", n))
		v.gaps = append(v.gaps, gap)
		return v, true
	}
	return phpValue{}, false
}

func doctrineDBALConnectionOperation(method string) bool {
	return method == "executequery" || method == "executestatement" || doctrineDBALFetch(method)
}

func doctrineDBALFetch(method string) bool {
	switch method {
	case "fetchone", "fetchassociative", "fetchnumeric", "fetchallassociative", "fetchallnumeric", "fetchfirstcolumn", "iterateassociative":
		return true
	}
	return false
}

func (f *phpFlow) doctrineDBALCall(n *sitter.Node, receiver phpValue, kind, method string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	switch kind {
	case "doctrine_connection":
		if len(values) == 0 {
			break
		}
		if method == "prepare" {
			return f.newDoctrineQuery(n, nodes[0], values[0], receiver, "doctrine_statement"), true
		}
		if doctrineDBALConnectionOperation(method) {
			query := f.newDoctrineQuery(n, nodes[0], values[0], receiver, "doctrine_statement")
			if len(values) > 1 {
				query = f.doctrineBind(n, query, values[1], false)
			}
			return f.doctrineDBALResult(n, f.runDoctrineQuery(n, query, doctrineDBALDriver), method), true
		}
	case "doctrine_statement":
		switch method {
		case "bindparam", "bindvalue":
			if len(values) >= 2 {
				f.writeObject(f.doctrineBind(n, receiver, values[1], true))
				return phpValue{}, true
			}
		case "executequery", "executestatement":
			if len(values) > 0 {
				receiver = f.doctrineBind(n, receiver, values[0], false)
			}
			return f.doctrineDBALResult(n, f.runDoctrineQuery(n, receiver, doctrineDBALDriver), method), true
		}
	case "doctrine_result":
		if doctrineDBALFetch(method) {
			return f.doctrineDBALResult(n, receiver, method), true
		}
	}
	return phpValue{}, false
}

func (f *phpFlow) doctrineDBALResult(n *sitter.Node, value phpValue, method string) phpValue {
	if doctrineDBALFetch(method) {
		v := f.sqlFetch(n, value)
		if method == "fetchone" && len(v.columns) == 1 {
			return f.projectValue(v, v.columns[0], n)
		}
		return v
	}
	if method == "executestatement" {
		return phpValue{}
	}
	value.binding = "doctrine_result"
	return value
}

func (f *phpFlow) doctrineORMCall(n *sitter.Node, receiver phpValue, kind, method string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	switch kind {
	case "doctrine_registry":
		if method == "getmanager" {
			return f.doctrineReceiver(n, doctrineManager), true
		}
	case "doctrine_repository":
		switch method {
		case "getentitymanager":
			return f.doctrineReceiver(n, doctrineManager), true
		case "createquerybuilder":
			if receiver.classDecl != nil {
				receiver.class = f.doctrineRepositoryEntity(receiver.classDecl)
			}
			return f.newDoctrineQuery(n, nil, phpValue{}, receiver, "doctrine_builder"), true
		}
		if doctrineFinderName(method) {
			return f.doctrineFinder(n, receiver, method, values)
		}
	case "doctrine_manager":
		switch method {
		case "getconnection":
			return f.doctrineReceiver(n, doctrineConnection), true
		case "find":
			return f.doctrineFinder(n, receiver, method, values)
		case "getrepository":
			if len(nodes) > 0 {
				return phpValue{binding: "doctrine_repository", class: f.doctrineClassArgument(nodes[0])}, true
			}
		case "createquerybuilder":
			return f.newDoctrineQuery(n, nil, phpValue{}, receiver, "doctrine_builder"), true
		case "createquery", "createnativequery":
			if len(values) > 0 {
				return f.newDoctrineQuery(n, nodes[0], values[0], receiver, "doctrine_query"), true
			}
		}
	case "doctrine_builder":
		if method == "getquery" {
			receiver.binding = "doctrine_query"
			f.set.objects++
			receiver.objectID = f.set.objects
			return receiver, true
		}
		if first, end, ok := doctrineBuilderText(method, len(values)); ok {
			if doctrineBuilderRoot(method) && len(nodes) > 0 {
				if class := f.doctrineClassArgument(nodes[0]); class != "" {
					receiver.class = class
				}
			}
			for i := first; i < end; i++ {
				if doctrineBuilderRoot(method) && len(values[i].deps) == 0 {
					// An entity class constant or alias is not constructed text.
					continue
				}
				receiver = f.doctrineQueryText(receiver, nodes[i], values[i])
			}
			f.writeObject(receiver)
			return receiver, true
		}
		if q, ok := f.doctrineORMParameters(n, receiver, method, values); ok {
			return q, true
		}
		// A fluent setter that adds no query text returns the same builder.
		// Dropping it would lose the text the chain already carries.
		return receiver, doctrineFluent(method)
	case "doctrine_query":
		switch method {
		case "getresult", "getoneornullresult", "getsingleresult", "getsinglescalarresult", "getarrayresult",
			"getscalarresult", "getsinglecolumnresult", "toiterable", "execute":
			f.runDoctrineQuery(n, receiver, doctrineORMDriver)
			switch method {
			case "getresult", "getarrayresult", "toiterable", "execute", "getoneornullresult", "getsingleresult":
				if receiver.class != "" {
					return f.doctrineResultEntity(n, receiver.class, method != "getoneornullresult" && method != "getsingleresult"), true
				}
			}
			return phpValue{}, true
		case "setdql", "setsql":
			if len(values) > 0 {
				receiver = f.doctrineQueryText(receiver, nodes[0], values[0])
				f.writeObject(receiver)
			}
			return receiver, true
		}
		if q, ok := f.doctrineORMParameters(n, receiver, method, values); ok {
			return q, true
		}
		return receiver, doctrineFluent(method)
	}
	return phpValue{}, false
}

func doctrineFinderName(method string) bool {
	switch method {
	case "find", "findby", "findoneby", "findall", "count":
		return true
	}
	return strings.HasPrefix(method, "findby") || strings.HasPrefix(method, "findoneby")
}

func (f *phpFlow) doctrineClassArgument(node *sitter.Node) string {
	if node == nil || node.Kind() != "class_constant_access_expression" || node.NamedChildCount() != 2 ||
		!strings.EqualFold(phpText(f.module, node.NamedChild(1)), "class") {
		return ""
	}
	name := node.NamedChild(0)
	return f.set.classIndex().qualify(f.module, phpText(f.module, name), name.StartByte())
}

func doctrineBuilderText(operation string, args int) (first, end int, ok bool) {
	switch operation {
	case "where", "andwhere", "orwhere", "having", "andhaving", "orhaving", "select", "addselect",
		"orderby", "addorderby", "groupby", "addgroupby", "set", "from", "update", "delete", "indexby":
		return 0, args, true
	case "add":
		// add(dqlPartName, dqlPart): the part is query text.
		return min(1, args), min(2, args), true
	case "join", "innerjoin", "leftjoin":
		return 3, min(4, args), true
	}
	return 0, 0, false
}

// doctrineBuilderRoot reports the operations whose first argument names the
// root entity of the query.
func doctrineBuilderRoot(operation string) bool {
	return operation == "from" || operation == "update" || operation == "delete"
}

// doctrineFluent lists QueryBuilder and Query setters that return the receiver
// and contribute neither query text nor a bound value.
// https://www.doctrine-project.org/projects/doctrine-orm/en/2.20/reference/query-builder.html
func doctrineFluent(method string) bool {
	switch method {
	case "setmaxresults", "setfirstresult", "distinct", "setcacheable", "setcacheregion", "setlifetime",
		"setcachemode", "resetdqlpart", "resetdqlparts", "sethint", "sethydrationmode", "usequerycache",
		"enableresultcache", "disableresultcache", "setresultcachelifetime", "setresultcacheid",
		"setlockmode", "setfetchmode", "setquerycachelifetime":
		return true
	}
	return false
}

func (f *phpFlow) doctrineORMParameters(n *sitter.Node, q phpValue, method string, values []phpValue) (phpValue, bool) {
	index := 0
	switch method {
	case "setparameter":
		index = 1
	case "setparameters":
	default:
		return phpValue{}, false
	}
	if len(values) > index {
		q = f.doctrineBind(n, q, values[index], true)
		f.writeObject(q)
	}
	return q, true
}

func (f *phpFlow) newDoctrineQuery(n, operand *sitter.Node, text, receiver phpValue, kind string) phpValue {
	f.set.objects++
	q := phpValue{
		binding: kind, class: receiver.class, objectID: f.set.objects,
		evidence: append(append([]analysis.Evidence{}, receiver.evidence...), f.module.evidence("sink_binding", n)),
	}
	if operand != nil {
		q = f.doctrineQueryText(q, operand, text)
	}
	return q
}

func (f *phpFlow) doctrineQueryText(q phpValue, node *sitter.Node, text phpValue) phpValue {
	_, literal := phpSQLText(text)
	text.built = !literal
	evidence := []analysis.Evidence{f.module.evidence("query_text", node)}
	for _, dep := range text.deps {
		for _, transfer := range dep.dep.Transfers {
			switch transfer.Kind {
			case "string_construction", "string_interpolation":
				transfer.Kind = "query_text"
				evidence = append(evidence, transfer)
			}
		}
	}
	q.sqlTextEvidence = phpDedupeEvidence(append(append([]analysis.Evidence{}, q.sqlTextEvidence...), evidence...))
	if q.sqlText != nil {
		text = phpCombine(*q.sqlText, text)
	}
	q.sqlText = &text
	return q
}

var doctrinePlaceholder = regexp.MustCompile(`\?|(?:^|[^:]):[A-Za-z_][A-Za-z0-9_]*`)

func (f *phpFlow) doctrineBind(n *sitter.Node, q phpValue, value phpValue, explicit bool) phpValue {
	q.sqlParams = append(append([]phpValue{}, q.sqlParams...), value)
	knownPlaceholder := false
	if q.sqlText != nil {
		if text, ok := phpSQLText(*q.sqlText); ok {
			knownPlaceholder = doctrinePlaceholder.MatchString(text)
		}
	}
	if explicit || knownPlaceholder {
		q.bindingControls = append(append([]analysis.Evidence{}, q.bindingControls...), f.module.evidence("parameter_binding", n))
	}
	return q
}

func (f *phpFlow) runDoctrineQuery(n *sitter.Node, query phpValue, driver string) phpValue {
	if query.sqlText == nil {
		return phpValue{}
	}
	return f.sqlClaim(n, nil, query.sqlParams, *query.sqlText, driver, "execute", query.evidence, query.bindingControls, query.sqlTextEvidence)
}
