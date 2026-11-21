package langjs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGraphQLResolverBindings(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", "import {ApolloServer} from '@apollo/server';\nconst typeDefs=`type Query { search(email: String!): String }`;\nfunction search(parent,args,context,info){return args.email;}\nnew ApolloServer({typeDefs,resolvers:{Query:{search}}});")
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 1 || r.Entries[0].GraphQL == nil || r.Entries[0].GraphQL.Type != "Query" || r.Entries[0].GraphQL.Field != "search" {
		t.Fatalf("missing verified schema coordinate: %+v", r.Entries)
	}
	if len(r.DispatchBindings) != 1 || r.DispatchBindings[0].Resolution != "resolved" || r.DispatchBindings[0].CallableID == "" {
		t.Fatalf("missing resolver target: %+v", r.DispatchBindings)
	}
	if len(r.InvocationContexts[0].Inputs) != 4 {
		t.Fatalf("distinct resolver roles missing: %+v", r.InvocationContexts)
	}
}

func TestGraphQLInputRoles(t *testing.T) {
	for _, tt := range []struct {
		name, expr string
		source     bool
		blocker    string
	}{
		{"args", "args.email", true, ""},
		{"literal bracket projection", "args['email']", true, ""},
		{"helper scalar", "identity(args.email)", true, ""},
		{"parent", "parent.email", false, "graphql_origin_unknown"},
		{"context", "context.email", false, "graphql_origin_unknown"},
		{"info", "info.email", false, "graphql_origin_unknown"},
		{"unknown transform", "unknown(args.email)", true, "unknown_transfer"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "import {ApolloServer} from '@apollo/server';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');function identity(x){return x;}const typeDefs=`scalar Email\ntype Query { search(email: Email): String }`;new ApolloServer({typeDefs,resolvers:{Query:{search:(parent,args,context,info)=>db.query('SELECT '+"+tt.expr+")}}});")
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := oneSQL(t, r)
			if (len(u.Dependencies) > 0) != tt.source {
				t.Fatalf("wrong role provenance: %+v", u.Dependencies)
			}
			if u.Completeness == nil || len(u.Completeness.Evidence["sink_binding"]) == 0 {
				t.Fatalf("missing real SQL contract: %+v", u.Completeness)
			}
			if tt.blocker != "" && !gapKind(u.Completeness.Blockers, tt.blocker) {
				t.Fatalf("missing %s: %+v", tt.blocker, u.Completeness)
			}
			if tt.source && tt.blocker == "" && len(u.Completeness.Blockers) > 0 {
				t.Fatalf("unexpected blocker: %+v", u.Completeness)
			}
			if u.Check == nil || u.Check.Selector == nil || u.Check.Method != "" || u.Check.Path != "" {
				t.Fatal("fabricated HTTP query check")
			}
			for _, in := range r.InvocationContexts[0].Inputs {
				if in.Role != "graphql.args" && in.Origin.Kind != "unknown" {
					t.Fatalf("non-args trusted: %+v", in)
				}
			}
		})
	}
}

func TestGraphQLPipelineAndBounds(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		t.Run(language, func(t *testing.T) {
			r, err := Analyze("testdata/"+language+"/graphql", "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 9 {
				t.Fatalf("entries=%d want9: %+v", len(r.Entries), r.Gaps)
			}
			if err := r.ValidateUses(); err != nil {
				t.Fatal(err)
			}
			sql := 0
			for _, u := range r.Uses {
				if u.Kind != "sql_query_candidate" {
					continue
				}
				sql++
				if u.Completeness == nil || len(u.Completeness.Evidence["input_source"]) == 0 {
					t.Fatalf("missing SQL source/completeness: %+v", u)
				}
				if u.EntryFacts.HTTP != nil || u.Check.Selector == nil {
					t.Fatal("fake HTTP")
				}
			}
			if sql != 6 {
				t.Fatalf("sql=%d want6 entries=%+v bindings=%+v", sql, r.Entries, r.DispatchBindings)
			}
		})
	}
}

func TestGraphQLResolverBindingsVariants(t *testing.T) {
	for _, tt := range []struct {
		name, source      string
		entries, resolved int
		gap               string
	}{
		{"instances", "function shared(p,a){return a.email;}const typeDefs=`type Query { search(email:String): String }`;new ApolloServer({typeDefs,resolvers:{Query:{search:shared}}});new ApolloServer({typeDefs,resolvers:{Query:{search:shared}}});", 2, 2, ""},
		{"inline and object", "new ApolloServer({typeDefs:`type Query { search: String } type User { name: String }`,resolvers:{Query:{search:()=>''},User:{name:(parent)=>parent.name}}});", 2, 2, "graphql_parent_result_unresolved"},
		{"default parameter", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:(parent,args={})=>''}}});", 1, 0, "graphql_parameters_unresolved"},
		{"mutable map", "const resolvers={Query:{search:()=>''}};resolvers.Query.search=other;new ApolloServer({typeDefs:`type Query { search: String }`,resolvers});", 1, 0, "graphql_resolvers_unresolved"},
		{"escaped map", "const resolvers={Query:{search:()=>''}};mutate(resolvers);new ApolloServer({typeDefs:`type Query { search: String }`,resolvers});", 1, 0, "graphql_resolvers_unresolved"},
		{"aliased map", "const resolvers={Query:{search:()=>''}};const alias=resolvers;alias.Query.search=other;new ApolloServer({typeDefs:`type Query { search: String }`,resolvers});", 1, 0, "graphql_resolvers_unresolved"},
		{"runtime object hook", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:()=>'',__isTypeOf:unknownHook}}});", 1, 0, "graphql_resolver_map_unresolved"},
		{"custom scalar execution", "new ApolloServer({typeDefs:`scalar Email type Query { search(email:Email): String }`,resolvers:{Email:customScalar,Query:{search:()=>''}}});", 1, 0, "graphql_resolvers_unresolved"},
		{"shorthand options", "const plugins=[];new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:()=>''}},plugins});", 1, 0, "graphql_config_unresolved"},
		{"additional options", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:()=>''}},plugins:[plugin]});", 1, 0, "graphql_config_unresolved"},
		{"defaults", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{}});", 1, 0, "graphql_default_resolver_unresolved"},
		{"runtime map", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:compose()});", 1, 0, "graphql_resolvers_unresolved"},
		{"spread map", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{...other,search:()=>''}}});", 1, 0, "graphql_resolver_map_unresolved"},
		{"wrapper", "function shared(p,a){return a.email;}new ApolloServer({typeDefs:`type Query { search(email:String): String }`,resolvers:{Query:{search:guard(shared)}}});", 1, 0, "graphql_resolver_unresolved"},
		{"mutated function", "let shared=(p,a)=>a.email;shared=other;new ApolloServer({typeDefs:`type Query { search(email:String): String }`,resolvers:{Query:{search:shared}}});", 1, 0, "graphql_resolver_unresolved"},
		{"shadowed constructor", "function setup(ApolloServer){new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:()=>''}}})}", 0, 0, "graphql_constructor_unresolved"},
		{"single arrow shadow", "const setup=ApolloServer=>new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:()=>''}}});", 0, 0, "graphql_constructor_unresolved"},
		{"destructured args", "new ApolloServer({typeDefs:`type Query { search(email:String): String }`,resolvers:{Query:{search:(p,{email})=>email}}});", 1, 0, "graphql_parameters_unresolved"},
		{"subscription", "new ApolloServer({typeDefs:`type Subscription { changed: String }`,resolvers:{Subscription:{changed:()=>''}}});", 1, 0, "graphql_subscription_unsupported"},
		{"duplicate map field", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search:()=>'',search:unknown}}});", 1, 0, "graphql_resolver_map_unresolved"},
		{"method", "new ApolloServer({typeDefs:`type Query { search: String }`,resolvers:{Query:{search(){return 'x'}}}});", 1, 1, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "import {ApolloServer} from '@apollo/server';"+tt.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			resolved := 0
			gaps := append([]analysis.Gap{}, r.Gaps...)
			instances := map[string]bool{}
			callables := map[string]bool{}
			for _, e := range r.Entries {
				gaps = append(gaps, e.Gaps...)
				instances[e.InstanceID] = true
				if strings.Contains(e.InstanceID, "unresolved") {
					t.Fatal("schema instance lacks snapshot hash")
				}
			}
			for _, b := range r.DispatchBindings {
				if b.Resolution == "resolved" {
					resolved++
					callables[b.CallableID] = true
				}
			}
			if len(r.Entries) != tt.entries || resolved != tt.resolved || tt.gap != "" && !gapKind(gaps, tt.gap) {
				t.Fatalf("entries=%d resolved=%d gaps=%+v", len(r.Entries), resolved, gaps)
			}
			if tt.name == "instances" && (len(instances) != 2 || len(callables) != 1 || r.InvocationContexts[0].ID == r.InvocationContexts[1].ID) {
				t.Fatal("schema/callable/context identity collapsed")
			}
		})
	}
}

func TestGraphQLPipelineAndBoundsControls(t *testing.T) {
	for _, tt := range []struct{ name, sdl, gap string }{
		{"extension", "type Query { a: String } extend type Query { b: String }", "graphql_sdl_unsupported"},
		{"directive", "type Query { a(email:String @format): String }", "graphql_sdl_unsupported"},
		{"custom root", "schema { query: Root } type Root { a: String }", "graphql_sdl_unsupported"},
		{"interpolation", "type Query { a: String } ${extra}", "graphql_schema_unresolved"},
		{"default value", "type Query { a(email:String=\"safe\"): String }", "graphql_sdl_unsupported"},
		{"malformed", "type Query { a: [String }", "graphql_sdl_unsupported"},
		{"duplicate", "type Query { a: String a: String }", "graphql_sdl_unsupported"},
		{"comment fake", "# type Query { fake: String }\ntype Query { real: String }", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "import {ApolloServer} from '@apollo/server';new ApolloServer({typeDefs:`"+tt.sdl+"`,resolvers:{Query:{a:()=>''}}});")
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			gaps := append([]analysis.Gap{}, r.Gaps...)
			for _, e := range r.Entries {
				gaps = append(gaps, e.Gaps...)
				if tt.gap != "" && r.Handler(e.ID) != nil {
					t.Fatal("unsupported SDL acquired resolved callable")
				}
				if e.GraphQL.Field == "fake" {
					t.Fatal("comment parsed as schema")
				}
			}
			if tt.gap != "" && !gapKind(gaps, tt.gap) {
				t.Fatalf("missing %s: %+v", tt.gap, gaps)
			}
		})
	}
	t.Run("field limit deterministic", func(t *testing.T) {
		root := t.TempDir()
		var s strings.Builder
		s.WriteString("import {ApolloServer} from '@apollo/server';new ApolloServer({typeDefs:`type Query { ")
		for i := 0; i < 130; i++ {
			fmt.Fprintf(&s, "f%d: String\n", i)
		}
		s.WriteString("}`,resolvers:{}});")
		writeSource(t, root, "app.js", s.String())
		a, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		b, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if !bytes.Equal(x, y) || len(a.Entries) != 128 || !gapKind(a.Gaps, "graphql_registration_limit") {
			t.Fatalf("limit/determinism: %d %+v", len(a.Entries), a.Gaps)
		}
	})
	t.Run("local SDL escape", func(t *testing.T) {
		for _, symlink := range []bool{false, true} {
			root := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside.graphql")
			if err := os.WriteFile(outside, []byte("type Query { a: String }"), 0600); err != nil {
				t.Fatal(err)
			}
			path := "../outside.graphql"
			if symlink {
				path = "./outside.graphql"
				if err := os.Symlink(outside, filepath.Join(root, "outside.graphql")); err != nil {
					t.Fatal(err)
				}
			}
			writeSource(t, root, "app.js", "import {ApolloServer} from '@apollo/server';import typeDefs from '"+path+"';new ApolloServer({typeDefs,resolvers:{Query:{a:()=>''}}});")
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 0 || !gapKind(r.Gaps, "graphql_schema_unresolved") {
				t.Fatal("escaped source admitted")
			}
		}
	})
}

func TestGraphQLInputRolesTransfersAndUnknowns(t *testing.T) {
	for _, tt := range []struct {
		name, body   string
		dependencies bool
		gap          string
	}{
		{"alias scalar", "const email=args.email;return db.query('SELECT '+email)", true, ""},
		{"alias object", "const alias=args;return db.query('SELECT '+alias.email)", true, ""},
		{"helper object", "return read(args)", true, ""},
		{"call alone", "identity(args.email);return db.query('SELECT fixed')", false, ""},
		{"mutated object", "args.email=other;return db.query('SELECT '+args.email)", true, "graphql_input_mutation"},
		{"mutated alias original read", "const alias=args;alias.email=other;return db.query('SELECT '+args.email)", true, "graphql_input_mutation"},
		{"escaped object", "const alias=args;mutate(alias);return db.query('SELECT '+args.email)", true, "graphql_argument_escape"},
		{"mutated alias", "const alias=args;alias.email=other;return db.query('SELECT '+alias.email)", true, "graphql_input_mutation"},
		{"unknown field", "return db.query('SELECT '+args.unknown)", true, "graphql_projection_unresolved"},
		{"unknown aliased guard", "const email=args.email;guard(email);return db.query('SELECT '+email)", true, "input_helper_unresolved"},
		{"unknown bracket guard", "guard(args['email']);return db.query('SELECT '+args['email'])", true, "input_helper_unresolved"},
		{"unknown pre-use guard", "guard(args.email);return db.query('SELECT '+args.email)", true, "input_helper_unresolved"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "import {ApolloServer} from '@apollo/server';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');function identity(x){return x;}function read(input){return db.query('SELECT '+input.email)}new ApolloServer({typeDefs:`type Query { search(email:String):String }`,resolvers:{Query:{search:(parent,args)=>{"+tt.body+"}}}});")
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			var sql []analysis.CandidateUse
			for _, u := range r.Uses {
				if u.Kind == "sql_query_candidate" {
					sql = append(sql, u)
				}
			}
			if !tt.dependencies {
				if len(sql) != 0 {
					t.Fatal("call alone manufactured source-to-sink flow")
				}
				return
			}
			if len(sql) != 1 || len(sql[0].Dependencies) == 0 {
				t.Fatalf("missing actual transfer: %+v", sql)
			}
			if tt.name == "helper object" && !transferKind(sql[0], "parameter_binding", "input") {
				t.Fatal("helper object parameter witness missing")
			}
			if tt.gap != "" && !gapKind(sql[0].Completeness.Blockers, tt.gap) {
				t.Fatalf("missing blocker %s: %+v", tt.gap, sql[0].Completeness)
			}
		})
	}
}

func TestGraphQLProtectionContexts(t *testing.T) {
	root := "testdata/javascript/graphql"
	checks := []analysis.Check{
		{ID: "raw", Kind: "sql_query", Fields: []string{"args.email"}, Selector: &analysis.EntrySelector{Kind: "graphql", Type: "Query", Field: "raw"}},
		{ID: "missing", Kind: "sql_query", Fields: []string{"args.email"}, Selector: &analysis.EntrySelector{Kind: "graphql", Type: "Query", Field: "wrapped"}},
	}
	r, err := AnalyzeWithChecks(root, "server.js", checks)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			found++
			if u.EntryFacts.GraphQL.Field != "raw" || u.Check.ID != "raw" || len(u.Completeness.Evidence["input_source"]) == 0 {
				t.Fatal("typed check lost exact source/context")
			}
		}
	}
	if found != 1 || !gapKind(r.Gaps, "check_operation_missing") {
		t.Fatalf("wrong scoped evidence: sql=%d gaps=%+v", found, r.Gaps)
	}
}

func TestGraphQLPipelineAndBoundsBudgets(t *testing.T) {
	for _, tt := range []struct{ name, sdl string }{
		{"nested type", "type Query { a: " + strings.Repeat("[", 17) + "String" + strings.Repeat("]", 17) + " }"},
		{"token budget", "type Query {" + strings.Repeat("a: String\n", 11000) + "}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "import {ApolloServer} from '@apollo/server';new ApolloServer({typeDefs:`"+tt.sdl+"`,resolvers:{}});")
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if !gapKind(r.Gaps, "graphql_sdl_unsupported") {
				t.Fatal("SDL budget silently truncated")
			}
		})
	}
	t.Run("scan record budget", func(t *testing.T) {
		root := t.TempDir()
		var src strings.Builder
		src.WriteString("import {ApolloServer} from '@apollo/server';const typeDefs=`type Query {")
		for i := 0; i < 128; i++ {
			fmt.Fprintf(&src, "f%d:String\n", i)
		}
		src.WriteString("}`;\n")
		for i := 0; i < 17; i++ {
			src.WriteString("new ApolloServer({typeDefs,resolvers:{}});\n")
		}
		writeSource(t, root, "app.js", src.String())
		a, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		b, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		x, _ := json.Marshal(a)
		y, _ := json.Marshal(b)
		if len(a.Entries) != 2000 || !gapKind(a.Gaps, "graphql_registration_limit") || !bytes.Equal(x, y) {
			t.Fatalf("record budget/determinism entries=%d gaps=%+v", len(a.Entries), a.Gaps)
		}
	})
}
