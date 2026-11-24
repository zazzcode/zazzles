package langjs

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Mass assignment for Express (lane decision D-4). A whole request bag that
// reaches a model write with no field list is a request-chosen set of property
// names on a stored object: Sequelize Model.create, build, bulkCreate and
// update, an instance update or set, Mongoose `new Model`, Model.create,
// findByIdAndUpdate and updateOne, and Object.assign on a model instance.
// The shape is dynamic_property_write: the ORM writes each key of the bag to
// the attribute of the same name. A `fields` option with a literal array, or a
// bag built as an object literal of named properties, records nothing.

// securityNameHints is the closed hint list of the Symfony lane's branch 1 D-4:
// property names lower-cased with separators removed. A hint never sets
// another role.
var securityNameHints = map[string]bool{
	"isadmin": true, "admin": true, "issuperuser": true, "superuser": true, "isstaff": true, "role": true, "roles": true,
	"permissions": true, "privileges": true, "password": true, "passwordhash": true, "apikey": true, "token": true,
	"resettoken": true, "verified": true, "isverified": true, "balance": true, "credit": true, "ownerid": true,
	"userid": true, "tenantid": true,
}

type modelAttribute struct {
	name string
	node *sitter.Node
}

type modelInfo struct {
	class      string
	attrs      []modelAttribute
	module     *sourceModule
	definition analysis.Evidence
	kind       string // sequelize | mongoose
}

// modelAttributes resolves a model identifier to its class, attribute list and
// definition evidence.
func (s *moduleSet) modelAttributes(m *sourceModule, name string) (modelInfo, bool) {
	id := s.modelIdentity(m, name, 0)
	switch {
	case strings.HasPrefix(id, "sequelize:"):
		rest := strings.TrimPrefix(id, "sequelize:")
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return modelInfo{}, false
		}
		mod, class := s.modules[rest[:i]], rest[i+1:]
		if mod == nil {
			return modelInfo{}, false
		}
		info := modelInfo{class: class, module: mod, kind: "sequelize"}
		if ev := s.modelEvidence[id]; len(ev) > 0 {
			info.definition = ev[0]
			info.definition.Kind = "target_class"
		}
		walkCalls(mod.tree.RootNode(), func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" || memberName(mod, fn) != "init" {
				return
			}
			if obj := fn.ChildByFieldName("object"); obj == nil || obj.Utf8Text(mod.src) != class {
				return
			}
			if o := unwrapTS(firstArg(args)); o != nil && o.Kind() == "object" && len(info.attrs) == 0 {
				info.attrs = objectAttributes(mod, o)
			}
		})
		return info, true
	case strings.HasPrefix(id, "mongoose:"):
		info := modelInfo{class: strings.TrimPrefix(id, "mongoose:"), module: m, kind: "mongoose"}
		if ev := s.modelEvidence[id]; len(ev) > 0 {
			info.definition = ev[0]
			info.definition.Kind = "target_class"
		}
		v := topVariable(m, name)
		if v != nil && v.Kind() == "call_expression" {
			if args := v.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() > 1 {
				schema := unwrapTS(args.NamedChild(1))
				if schema != nil && schema.Kind() == "identifier" {
					schema = unwrapTS(topVariable(m, schema.Utf8Text(m.src)))
				}
				if schema != nil && schema.Kind() == "new_expression" {
					if sargs := schema.ChildByFieldName("arguments"); sargs != nil {
						if o := unwrapTS(firstArg(sargs)); o != nil && o.Kind() == "object" {
							info.attrs = objectAttributes(m, o)
						}
					}
				}
			}
		}
		return info, true
	}
	return modelInfo{}, false
}

func objectAttributes(m *sourceModule, o *sitter.Node) []modelAttribute {
	var attrs []modelAttribute
	for i := uint(0); i < o.NamedChildCount(); i++ {
		c := o.NamedChild(i)
		switch c.Kind() {
		case "pair":
			if k := c.ChildByFieldName("key"); k != nil {
				attrs = append(attrs, modelAttribute{strings.Trim(k.Utf8Text(m.src), `"'`), c})
			}
		case "shorthand_property_identifier":
			attrs = append(attrs, modelAttribute{c.Utf8Text(m.src), c})
		}
	}
	return attrs
}

// securityFields is the census of a model's attributes: credential where a
// set accessor stored a digest (D-6), name_hint where the name is on the hint
// list. Roles are listed in this order; each has one evidence item.
func (s *moduleSet) securityFields(info modelInfo) ([]analysis.SecurityField, []string) {
	var fields []analysis.SecurityField
	var mapped []string
	for _, a := range info.attrs {
		mapped = append(mapped, a.name)
		var roles []string
		var evidence []analysis.Evidence
		ev := info.module.evidence("model_attribute", a.node)
		if s.credentialAttrs[a.name] {
			roles, evidence = append(roles, analysis.RoleCredential), append(evidence, ev)
		}
		if securityNameHints[strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(a.name))] {
			roles, evidence = append(roles, analysis.RoleNameHint), append(evidence, ev)
		}
		if len(roles) > 0 {
			fields = append(fields, analysis.SecurityField{StorageKey: "js-attribute:" + info.class + "." + a.name, Roles: roles, Evidence: evidence})
		}
	}
	return fields, mapped
}

func (s *moduleSet) massAssignmentCandidates(out *analysis.AnalysisReport) {
	callables := map[string]analysis.Callable{}
	for _, c := range out.Callables {
		callables[c.ID] = c
	}
	bindings := map[string]string{}
	for _, b := range out.DispatchBindings {
		bindings[b.EntryID] = b.CallableID
	}
	entries := append([]analysis.EntryPoint{}, out.Entries...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		if e.Kind != "http" || e.HTTP == nil || e.HTTP.Method == "USE" || e.HTTP.Framework != "express" {
			continue
		}
		if e.Access != nil && e.Access.RejectsAll {
			continue
		}
		def := callables[bindings[e.ID]].Definition.Span
		m := s.modules[def.File]
		if m == nil || def.File == "" {
			continue
		}
		node := parse.NodeAt(m.tree.RootNode(), def.StartByte, def.EndByte)
		if node == nil {
			continue
		}
		fn, body := handlerFunction(node)
		if body == nil || fn == nil {
			continue
		}
		params := plainOrDestructuredParameters(fn, m.src)
		walkCalls(body, func(call *sitter.Node) { s.massCall(out, e, m, fn, params, call) })
		walkNews(body, func(n *sitter.Node) { s.massNew(out, e, m, fn, params, n) })
	}
}

func walkNews(n *sitter.Node, visit func(*sitter.Node)) {
	if n == nil {
		return
	}
	if n.Kind() == "new_expression" {
		visit(n)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		walkNews(n.NamedChild(i), visit)
	}
}

func (s *moduleSet) massNew(out *analysis.AnalysisReport, e analysis.EntryPoint, m *sourceModule, fn *sitter.Node, p handlerParams, n *sitter.Node) {
	if f := enclosingFunction(n); f != nil && f.StartByte() != fn.StartByte() {
		return
	}
	ctor, args := n.ChildByFieldName("constructor"), n.ChildByFieldName("arguments")
	if ctor == nil || ctor.Kind() != "identifier" || args == nil || shadowed(n, ctor.Utf8Text(m.src), m.src) {
		return
	}
	info, ok := s.modelAttributes(m, ctor.Utf8Text(m.src))
	if !ok || info.kind != "mongoose" {
		return
	}
	if bag := s.wholeBag(m, firstArg(args), p, info); bag != nil {
		s.recordMass(out, e, m, n, bag, info, nil, "")
	}
}

func (s *moduleSet) massCall(out *analysis.AnalysisReport, e analysis.EntryPoint, m *sourceModule, fn *sitter.Node, p handlerParams, call *sitter.Node) {
	if f := enclosingFunction(call); f != nil && f.StartByte() != fn.StartByte() {
		return
	}
	cfn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if cfn == nil || args == nil || cfn.Kind() != "member_expression" {
		return
	}
	obj := cfn.ChildByFieldName("object")
	if obj == nil || obj.Kind() != "identifier" {
		return
	}
	name, method := obj.Utf8Text(m.src), memberName(m, cfn)
	var nodes []*sitter.Node
	for i := uint(0); i < args.NamedChildCount(); i++ {
		if c := args.NamedChild(i); c.Kind() != "comment" {
			nodes = append(nodes, c)
		}
	}
	if len(nodes) == 0 {
		return
	}
	var info modelInfo
	var bagArg *sitter.Node
	var optionsArg *sitter.Node
	switch {
	case name == "Object" && method == "assign" && len(nodes) >= 2:
		model, ok := s.instanceModel(m, nodes[0])
		if !ok {
			return
		}
		info, bagArg = model, nodes[1]
	case !shadowed(call, name, m.src) && strings.HasPrefix(s.modelIdentity(m, name, 0), "sequelize:"):
		model, _ := s.modelAttributes(m, name)
		info = model
		switch method {
		case "create", "build", "bulkCreate", "update":
			bagArg = nodes[0]
			if len(nodes) > 1 {
				optionsArg = nodes[1]
			}
		}
	case !shadowed(call, name, m.src) && strings.HasPrefix(s.modelIdentity(m, name, 0), "mongoose:"):
		model, _ := s.modelAttributes(m, name)
		info = model
		switch method {
		case "create":
			bagArg = nodes[0]
		case "findByIdAndUpdate", "updateOne":
			if len(nodes) > 1 {
				bagArg = nodes[1]
			}
		}
	default:
		if method == "update" || method == "set" {
			if model, ok := s.instanceModel(m, obj); ok && model.kind == "sequelize" {
				info, bagArg = model, nodes[0]
				if len(nodes) > 1 {
					optionsArg = nodes[1]
				}
			}
		}
	}
	if bagArg == nil {
		return
	}
	if optionsArg != nil && hasFieldList(m, optionsArg) {
		return
	}
	if bag := s.wholeBag(m, bagArg, p, info); bag != nil {
		s.recordMass(out, e, m, call, bag, info, nil, "")
	}
}

// instanceModel resolves an identifier bound by `const x = await Model.findByPk(...)`,
// `findOne`, `Model.build(...)` or `new Model(...)` to the model.
func (s *moduleSet) instanceModel(m *sourceModule, id *sitter.Node) (modelInfo, bool) {
	if id == nil || id.Kind() != "identifier" {
		return modelInfo{}, false
	}
	init := unwrapTS(localConst(m, id, id.Utf8Text(m.src)))
	if init != nil && init.Kind() == "await_expression" && init.NamedChildCount() == 1 {
		init = init.NamedChild(0)
	}
	if init == nil {
		return modelInfo{}, false
	}
	switch init.Kind() {
	case "new_expression":
		if ctor := init.ChildByFieldName("constructor"); ctor != nil && ctor.Kind() == "identifier" {
			return s.modelAttributes(m, ctor.Utf8Text(m.src))
		}
	case "call_expression":
		fn := init.ChildByFieldName("function")
		if fn != nil && fn.Kind() == "member_expression" {
			switch memberName(m, fn) {
			case "findByPk", "findOne", "build", "findById":
				if o := fn.ChildByFieldName("object"); o != nil && o.Kind() == "identifier" {
					return s.modelAttributes(m, o.Utf8Text(m.src))
				}
			}
		}
	}
	return modelInfo{}, false
}

func hasFieldList(m *sourceModule, options *sitter.Node) bool {
	o := unwrapTS(options)
	if o == nil || o.Kind() != "object" {
		return false
	}
	f := property(o, "fields", m.src)
	return f != nil && unwrapTS(f).Kind() == "array"
}

// wholeBag returns the node that is a whole request bag, or nil: req.body,
// req.query, a destructured container, a constant alias of one, or an object
// that spreads one with no later override of every model attribute.
func (s *moduleSet) wholeBag(m *sourceModule, x *sitter.Node, p handlerParams, info modelInfo) *sitter.Node {
	x = unwrapTS(x)
	if x == nil {
		return nil
	}
	switch x.Kind() {
	case "member_expression":
		if obj, prop := x.ChildByFieldName("object"), x.ChildByFieldName("property"); obj != nil && prop != nil && obj.Kind() == "identifier" &&
			obj.Utf8Text(m.src) == p.request && (prop.Utf8Text(m.src) == "body" || prop.Utf8Text(m.src) == "query") {
			return x
		}
	case "identifier":
		name := x.Utf8Text(m.src)
		if p.containers[name] && (name == "body" || name == "query") {
			return x
		}
		if v := unwrapTS(localConst(m, x, name)); v != nil {
			if s.wholeBag(m, v, p, info) != nil {
				return x
			}
		}
	case "object":
		var bag *sitter.Node
		overridden := map[string]bool{}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			c := x.NamedChild(i)
			switch c.Kind() {
			case "spread_element":
				if c.NamedChildCount() == 1 {
					if b := s.wholeBag(m, c.NamedChild(0), p, info); b != nil {
						bag = b
						overridden = map[string]bool{}
					}
				}
			case "pair":
				if k := c.ChildByFieldName("key"); k != nil && bag != nil {
					overridden[strings.Trim(k.Utf8Text(m.src), `"'`)] = true
				}
			}
		}
		if bag != nil {
			all := len(info.attrs) > 0
			for _, a := range info.attrs {
				all = all && overridden[a.name]
			}
			if !all {
				return bag
			}
		}
	}
	return nil
}

func (s *moduleSet) recordMass(out *analysis.AnalysisReport, e analysis.EntryPoint, m *sourceModule, write, bag *sitter.Node, info modelInfo, extra []analysis.Evidence, note string) {
	sink := m.evidence(analysis.MassAssignmentKind, write)
	source := m.evidence("input_source", bag)
	keyOrigin := m.evidence("key_origin", bag)
	operation := m.evidence("property_write", write)
	if note != "" {
		source.ModelText, keyOrigin.ModelText, operation.ModelText = note, note, note
	}
	fields, mapped := s.securityFields(info)
	if fields == nil {
		fields = []analysis.SecurityField{}
	}
	target := info.definition
	if target.Span.File == "" {
		target = info.module.evidence("target_class", info.module.tree.RootNode())
	}
	facts := &analysis.MassAssignmentFacts{
		Shape: analysis.MassAssignmentPropertyWrite, TargetClass: info.class, TargetStored: "yes",
		SecurityFields: fields, MappedFields: mapped,
	}
	flow := append([]analysis.Evidence{asEvidenceKind(sink, "operation")}, extra...)
	evidence := map[string][]analysis.Evidence{
		"input_source": {source}, "key_origin": {keyOrigin}, "property_write": {operation}, "target_class": {target},
		"control_flow": flow, "sink_binding": {asEvidenceKind(sink, "sink_binding")},
	}
	if note != "" {
		// A generated endpoint has no handler callable; its registration is the
		// dispatch the claim rests on.
		evidence["dispatch_binding"] = []analysis.Evidence{e.Location}
	}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: e.ID, Kind: analysis.MassAssignmentKind, Sink: sink, MassAssignment: facts,
		Dependencies: []analysis.Dependency{{Source: source}},
		Gaps:         []analysis.Gap{}, Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "mass_assignment", Required: []string{"input_source", "key_origin", "property_write", "target_class", "control_flow"},
			Scope:    "One write of a whole request bag to a stored model, its target and the census roles of the target's fields.",
			Evidence: evidence,
			Blockers: []analysis.Gap{}, Coverage: []analysis.Gap{},
		},
	})
}
