package langjs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

const grpcProto = `syntax = "proto3";
package fixtures.search;
message Request { string email = 1; }
message Reply { string result = 1; }
service SearchService { rpc Search(Request) returns (Reply); }
`
const grpcSetup = `import * as grpc from '@grpc/grpc-js';
import * as loader from '@grpc/proto-loader';
const definition=loader.loadSync('./search.proto');
const api=grpc.loadPackageDefinition(definition);
const server=new grpc.Server();
`

func TestGRPCServiceBindings(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "search.proto", grpcProto)
	writeSource(t, root, "app.js", grpcSetup+`function search(call,callback) { callback(null,call.request); }
server.addService(api.fixtures.search.SearchService.service,{search});
const second=new grpc.Server();
second.addService(api.fixtures.search.SearchService.service,{Search:search});`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 2 {
		t.Fatalf("entries=%d want2; gaps=%+v", len(r.Entries), r.Gaps)
	}
	for _, e := range r.Entries {
		if e.GRPC == nil || e.GRPC.Package != "fixtures.search" || e.GRPC.Service != "SearchService" || e.GRPC.Method != "Search" || e.HTTP != nil || r.Handler(e.ID) == nil {
			t.Fatalf("unbound grpc entry: %+v bindings=%+v", e, r.DispatchBindings)
		}
	}
	if r.Entries[0].InstanceID == r.Entries[1].InstanceID || len(r.Callables) != 1 || r.InvocationContexts[0].ID == r.InvocationContexts[1].ID {
		t.Fatal("server/callable/context identity collapsed")
	}
	if err := r.ValidateUses(); err != nil {
		t.Fatal(err)
	}
}

func TestGRPCInputRolesAndControls(t *testing.T) {
	for _, tt := range []struct {
		name, body, gap string
		source          bool
	}{
		{"request", `return db.query('SELECT '+call.request.email)`, "", true},
		{"bracket", `return db.query('SELECT '+call['request']['email'])`, "", true},
		{"scalar alias", `const email=call.request.email;return db.query('SELECT '+email)`, "", true},
		{"object alias", `const input=call.request;return db.query('SELECT '+input.email)`, "", true},
		{"call alias", `const input=call;return db.query('SELECT '+input.request.email)`, "", true},
		{"helper scalar", `return db.query('SELECT '+identity(call.request.email))`, "", true},
		{"helper object", `return read(call.request)`, "", true},
		{"metadata", `return db.query('SELECT '+call.metadata.email)`, "grpc_origin_unknown", false},
		{"context", `return db.query('SELECT '+call.context.email)`, "grpc_origin_unknown", false},
		{"callback", `return db.query('SELECT '+callback.email)`, "grpc_origin_unknown", false},
		{"unknown", `return db.query('SELECT '+transform(call.request.email))`, "unknown_transfer", true},
		{"unknown guard", `guard(call.request.email);return db.query('SELECT '+call.request.email)`, "input_helper_unresolved", true},
		{"object escape", `const input=call.request;mutate(input);return db.query('SELECT '+input.email)`, "grpc_argument_escape", true},
		{"mutation", `call.request.email=other;return db.query('SELECT '+call.request.email)`, "grpc_input_mutation", false},
		{"undeclared", `return db.query('SELECT '+call.request.other)`, "grpc_projection_unresolved", true},
		{"camel field", `return db.query('SELECT '+call.request.userName)`, "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "search.proto", strings.Replace(grpcProto, "string email = 1;", "string email = 1; string user_name=2;", 1))
			writeSource(t, root, "app.js", grpcSetup+`import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');function identity(x){return x;}function read(input){return db.query('SELECT '+input.email)}server.addService(api.fixtures.search.SearchService.service,{search:(call,callback)=>{`+tt.body+`}});`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := oneSQL(t, r)
			if (len(u.Dependencies) > 0) != tt.source {
				t.Fatalf("source roles: %+v", u.Dependencies)
			}
			if u.Completeness == nil || len(u.Completeness.Evidence["sink_binding"]) == 0 {
				t.Fatalf("missing real completeness: %+v", u)
			}
			if tt.gap != "" && !gapKind(u.Completeness.Blockers, tt.gap) {
				t.Fatalf("missing %s: %+v", tt.gap, u.Completeness)
			}
			if tt.source && tt.gap == "" && len(u.Completeness.Blockers) != 0 {
				t.Fatalf("unexpected blockers %+v", u.Completeness)
			}
			if u.Check == nil || u.Check.Selector == nil || u.Check.Selector.Kind != "grpc" || u.Check.Method != "" || u.Check.Path != "" {
				t.Fatal("fake HTTP check")
			}
			roles := map[string]string{}
			for _, input := range r.InvocationContexts[0].Inputs {
				roles[input.Role] = input.Origin.Kind
			}
			if roles["grpc.request"] != "external" || roles["grpc.metadata"] != "unknown" || roles["grpc.context"] != "unknown" || roles["grpc.callback"] != "unknown" {
				t.Fatalf("role collapse %+v", roles)
			}
		})
	}
	t.Run("calls do not prove value flow", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "search.proto", grpcProto)
		writeSource(t, root, "app.js", grpcSetup+`import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');function identity(x){return x}server.addService(api.fixtures.search.SearchService.service,{search:(call,callback)=>{identity(call.request.email);return db.query('SELECT fixed')}});`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range r.Uses {
			if u.Kind == "sql_query_candidate" {
				t.Fatal("unrelated call manufactured data flow")
			}
		}
	})
}

func TestGRPCPipeline(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		t.Run(language, func(t *testing.T) {
			root := "testdata/" + language + "/grpc"
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 11 {
				t.Fatalf("entries=%d gaps=%+v", len(r.Entries), r.Gaps)
			}
			count := 0
			for _, u := range r.Uses {
				if u.Kind == "sql_query_candidate" {
					count++
					if len(u.Dependencies) == 0 || u.Completeness == nil {
						t.Fatalf("missing actual SQL flow %+v", u)
					}
				}
			}
			if count != 6 {
				t.Fatalf("sql=%d want6", count)
			}
			again, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			a, _ := json.Marshal(r)
			b, _ := json.Marshal(again)
			if !bytes.Equal(a, b) {
				t.Fatal("nondeterministic gRPC report")
			}
			if err := r.ValidateUses(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGRPCUnknownAndStreaming(t *testing.T) {
	for _, tt := range []struct {
		name, setup, tail, proto, gap string
		entries, resolved             int
	}{
		{name: "dynamic descriptor", tail: `server.addService(runtime.service,{search:(call)=>call.request.email});`, gap: "grpc_descriptor_unresolved"},
		{name: "generated stub", setup: `import * as grpc from "@grpc/grpc-js";const server=new grpc.Server();`, tail: `import api from './generated';server.addService(api.SearchService.service,{search:(call)=>call.request.email});`, gap: "grpc_descriptor_unresolved"},
		{name: "missing proto", setup: strings.Replace(grpcSetup, "search.proto", "missing.proto", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{});`, gap: "grpc_proto_unresolved"},
		{name: "dynamic path", setup: strings.Replace(grpcSetup, "'./search.proto'", "runtimePath", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{});`, gap: "grpc_descriptor_unresolved"},
		{name: "include paths", setup: strings.Replace(grpcSetup, "'./search.proto'", "'./search.proto',{includeDirs:['../external']}", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{search:(call)=>call.request.email});`, gap: "grpc_loader_options_unresolved", entries: 1},
		{name: "interceptor", setup: strings.Replace(grpcSetup, "new grpc.Server()", "new grpc.Server({interceptors:[unknown]})", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{search:(call)=>call.request.email});`, gap: "grpc_interceptor_unresolved", entries: 1},
		{name: "mismatch", tail: `server.addService(api.fixtures.search.SearchService.service,{SearchOther:(call)=>call.request.email});`, gap: "grpc_method_mismatch", entries: 1},
		{name: "missing handler", tail: `server.addService(api.fixtures.search.SearchService.service,{});`, gap: "grpc_handler_unresolved", entries: 1},
		{name: "wrapper", tail: `server.addService(api.fixtures.search.SearchService.service,{search:wrap(handler)});`, gap: "grpc_handler_unresolved", entries: 1},
		{name: "default parameter", tail: `server.addService(api.fixtures.search.SearchService.service,{search:(call=other)=>call.request.email});`, gap: "grpc_parameters_unresolved", entries: 1},
		{name: "destructured parameter", tail: `server.addService(api.fixtures.search.SearchService.service,{search:({request})=>request.email});`, gap: "grpc_parameters_unresolved", entries: 1},
		{name: "streaming", proto: strings.Replace(grpcProto, "Search(Request) returns (Reply)", "Search(stream Request) returns (stream Reply)", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{search:(call)=>call.request.email});`, gap: "grpc_streaming_unsupported", entries: 1},
		{name: "import proto", proto: grpcProto + `import "other.proto";`, tail: `server.addService(api.fixtures.search.SearchService.service,{search:(call)=>call.request.email});`, gap: "grpc_proto_unsupported", entries: 1},
		{name: "proto2", proto: strings.Replace(grpcProto, "proto3", "proto2", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{});`, gap: "grpc_proto_unsupported"},
		{name: "malformed", proto: strings.TrimSuffix(grpcProto, "}\n"), tail: `server.addService(api.fixtures.search.SearchService.service,{});`, gap: "grpc_proto_unsupported", entries: 1},
		{name: "comment fake", proto: `// service Fake { rpc Bad(Request) returns (Reply); }
` + grpcProto, tail: `server.addService(api.fixtures.search.SearchService.service,{search(call){return call.request.email}});`, entries: 1, resolved: 1},
		{name: "CommonJS", setup: `const grpc=require('@grpc/grpc-js');const loader=require('@grpc/proto-loader');const definition=loader.loadSync('./search.proto');const api=grpc.loadPackageDefinition(definition);const server=new grpc.Server();`, tail: `server.addService(api.fixtures.search.SearchService.service,{search(call){return call.request.email}});`, entries: 1, resolved: 1},
		{name: "named imports", setup: `import {Server,loadPackageDefinition} from '@grpc/grpc-js';import {loadSync} from '@grpc/proto-loader';const definition=loadSync('./search.proto');const api=loadPackageDefinition(definition);const server=new Server();`, tail: `server.addService(api.fixtures.search.SearchService.service,{Search:call=>call.request.email});`, entries: 1, resolved: 1},
		{name: "fake addService", setup: `const server={addService(){}};`, tail: `server.addService(api.fixtures.search.SearchService.service,{search:handler});`, gap: "grpc_receiver_unresolved"},
		{name: "shadowed receiver", tail: `function local(server){server.addService(api.fixtures.search.SearchService.service,{search:handler})}`, gap: "grpc_receiver_unresolved"},
		{name: "descriptor mutation", tail: `mutate(api);server.addService(api.fixtures.search.SearchService.service,{search:handler});`, gap: "grpc_descriptor_unresolved"},
		{name: "descriptor property mutation", tail: `api.fixtures=runtime;server.addService(api.fixtures.search.SearchService.service,{search:handler});`, gap: "grpc_descriptor_unresolved"},
		{name: "server unknown method", tail: `server.configureInterceptors(unknown);server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.email});`, gap: "grpc_receiver_unresolved"},
		{name: "descriptor unknown method", tail: `api.mutate();server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.email});`, gap: "grpc_descriptor_unresolved"},
		{name: "server escape", tail: `configure(server);server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.email});`, gap: "grpc_receiver_unresolved"},
		{name: "impl mutation", tail: `const impl={search:call=>call.request.email};mutate(impl);server.addService(api.fixtures.search.SearchService.service,impl);`, gap: "grpc_implementation_unresolved", entries: 1},
		{name: "literal map binding", tail: `const impl={search:call=>call.request.email};server.addService(api.fixtures.search.SearchService.service,impl);`, entries: 1, resolved: 1},
		{name: "fake escape", tail: `const impl={search:call=>call.request.email};evil.addService(other,impl);server.addService(api.fixtures.search.SearchService.service,impl);`, entries: 1, gap: "grpc_implementation_unresolved"},
		{name: "framework escape", tail: `configure(grpc);server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.email});`, entries: 1, gap: "grpc_framework_unresolved"},
		{name: "field type missing", proto: strings.Replace(grpcProto, "string email", "Missing email", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{});`, entries: 1, gap: "grpc_proto_unsupported"},
		{name: "invalid labels", proto: strings.Replace(grpcProto, "string email", "optional repeated string email", 1), tail: `server.addService(api.fixtures.search.SearchService.service,{});`, gap: "grpc_proto_unsupported"},
		{name: "repeated registration sites", tail: `server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.email});server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.email});`, entries: 2, resolved: 2},
		{name: "alias service", tail: `const service=api.fixtures.search.SearchService.service;server.addService(service,{search:call=>call.request.email});`, entries: 1, resolved: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			proto := tt.proto
			if proto == "" {
				proto = grpcProto
			}
			setup := tt.setup
			if setup == "" {
				setup = grpcSetup
			}
			writeSource(t, root, "search.proto", proto)
			writeSource(t, root, "app.js", setup+tt.tail)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			gaps := append([]analysis.Gap{}, r.Gaps...)
			resolved := 0
			for _, e := range r.Entries {
				gaps = append(gaps, e.Gaps...)
			}
			for _, b := range r.DispatchBindings {
				if b.Resolution == "resolved" {
					resolved++
				}
			}
			if len(r.Entries) != tt.entries || resolved != tt.resolved || tt.gap != "" && !gapKind(gaps, tt.gap) {
				t.Fatalf("entries=%d resolved=%d gaps=%+v", len(r.Entries), resolved, gaps)
			}
			for _, g := range gaps {
				if strings.HasPrefix(g.Kind, "grpc_") && (g.At.File == "" || g.At.EndByte <= g.At.StartByte) {
					t.Fatalf("unlocated gap %+v", g)
				}
			}
		})
	}
	t.Run("registration limit", func(t *testing.T) {
		root := t.TempDir()
		proto := `syntax="proto3";message Request{} message Reply{} service S {`
		for i := 0; i < 130; i++ {
			proto += fmt.Sprintf("rpc M%d(Request) returns (Reply);", i)
		}
		proto += "}"
		writeSource(t, root, "search.proto", proto)
		writeSource(t, root, "app.js", grpcSetup+`server.addService(api.S.service,{});`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 128 || !gapKind(r.Gaps, "grpc_registration_limit") {
			t.Fatalf("silent expansion truncation %+v", r.Gaps)
		}
	})
	t.Run("proto token limit", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "search.proto", grpcProto+strings.Repeat("message X{}", 9000))
		writeSource(t, root, "app.js", grpcSetup+`server.addService(api.fixtures.search.SearchService.service,{});`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if !gapKind(r.Gaps, "grpc_proto_unsupported") || !strings.Contains(fmt.Sprint(r.Gaps), "token limit") {
			t.Fatal("proto budget not explicit")
		}
	})
	t.Run("root escape", func(t *testing.T) {
		for _, symlink := range []bool{false, true} {
			root := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside.proto")
			if err := os.WriteFile(outside, []byte(grpcProto), 0600); err != nil {
				t.Fatal(err)
			}
			path := "../outside.proto"
			if symlink {
				path = "./outside.proto"
				if err := os.Symlink(outside, filepath.Join(root, "outside.proto")); err != nil {
					t.Fatal(err)
				}
			}
			writeSource(t, root, "app.js", strings.Replace(grpcSetup, "./search.proto", path, 1)+`server.addService(api.fixtures.search.SearchService.service,{});`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 0 || !gapKind(r.Gaps, "grpc_proto_unresolved") {
				t.Fatal("escaped proto admitted")
			}
		}
	})
}

func TestGRPCServiceBindingsMethodMapping(t *testing.T) {
	for _, tt := range []struct {
		name, method, implementation string
		resolved                     bool
	}{
		{"original name priority", "Search", `Search:unknown,search:call=>call.request.email`, false},
		{"snake fallback", "search_users", `searchUsers:call=>call.request.email`, true},
		{"acronym exact", "GetURL", `GetURL:call=>call.request.email`, true},
		{"acronym fallback unknown", "GetURL", `getURL:call=>call.request.email`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "search.proto", strings.Replace(grpcProto, "rpc Search(", "rpc "+tt.method+"(", 1))
			writeSource(t, root, "app.js", grpcSetup+`server.addService(api.fixtures.search.SearchService.service,{`+tt.implementation+`});`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 1 || (r.Handler(r.Entries[0].ID) != nil) != tt.resolved {
				t.Fatalf("method mapping mismatch %+v %+v", r.Entries, r.DispatchBindings)
			}
		})
	}
}

func TestGRPCPipelineSelectors(t *testing.T) {
	checks := []analysis.Check{
		{ID: "raw", Kind: "sql_query", Fields: []string{"request.email"}, Selector: &analysis.EntrySelector{Kind: "grpc", Service: "fixtures.search.SearchService", Method: "Raw"}},
		{ID: "absent", Kind: "sql_query", Fields: []string{"call.request.email"}, Selector: &analysis.EntrySelector{Kind: "grpc", Service: "fixtures.search.SearchService", Method: "Absent"}},
	}
	r, err := AnalyzeWithChecks("testdata/javascript/grpc", "server.js", checks)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			count++
			if u.EntryFacts.GRPC.Method != "Raw" || u.Check.ID != "raw" || len(u.Completeness.Evidence["input_source"]) == 0 {
				t.Fatal("typed selector lost exact source/context")
			}
		}
	}
	if count != 1 || !gapKind(r.Gaps, "check_operation_missing") {
		t.Fatalf("typed checks: sql=%d gaps=%+v", count, r.Gaps)
	}
}

func TestGRPCUnknownAndStreamingBudgets(t *testing.T) {
	t.Run("descriptor alias budget", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "search.proto", grpcProto)
		source := grpcSetup
		last := "api"
		for i := 0; i < 18; i++ {
			name := fmt.Sprintf("a%d", i)
			source += "const " + name + "=" + last + ";"
			last = name
		}
		writeSource(t, root, "app.js", source+`server.addService(`+last+`.fixtures.search.SearchService.service,{});`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 0 || !gapKind(r.Gaps, "grpc_descriptor_limit") {
			t.Fatal("descriptor expansion bound lost")
		}
	})
	t.Run("scan record budget", func(t *testing.T) {
		root := t.TempDir()
		proto := `syntax="proto3";message Request{} message Reply{} service S {`
		for i := 0; i < 128; i++ {
			proto += fmt.Sprintf("rpc M%d(Request) returns (Reply);", i)
		}
		proto += "}"
		source := grpcSetup
		for i := 0; i < 17; i++ {
			source += `server.addService(api.S.service,{});`
		}
		writeSource(t, root, "search.proto", proto)
		writeSource(t, root, "app.js", source)
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
		if len(a.Entries) != 2000 || !gapKind(a.Gaps, "grpc_registration_limit") || !bytes.Equal(x, y) {
			t.Fatalf("record limit/determinism: entries=%d gaps=%+v", len(a.Entries), a.Gaps)
		}
	})
	t.Run("registration syntax error", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "search.proto", grpcProto)
		writeSource(t, root, "app.js", grpcSetup+`server.addService(???);`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 0 || !gapKind(r.Gaps, "parse_error") {
			t.Fatal("parser uncertainty lost")
		}
	})
}

func TestGRPCInputRolesAndControlsFieldNames(t *testing.T) {
	for _, tt := range []struct{ name, field, projection, options string }{
		{"ordinary camel", "user_name", "userName", ""},
		{"leading underscore", "_email", "_email", ""},
		{"digit underscore", "user_2", "user_2", ""},
		{"double underscore", "user__name", "user_Name", ""},
		{"uppercase underscore", "user_Name", "user_Name", ""},
		{"keep case", "user_name", "user_name", ",{keepCase:true}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "search.proto", strings.Replace(grpcProto, "string email", "string "+tt.field, 1))
			source := strings.Replace(grpcSetup, "'./search.proto'", "'./search.proto'"+tt.options, 1)
			writeSource(t, root, "app.js", source+`import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');server.addService(api.fixtures.search.SearchService.service,{search:call=>db.query('SELECT '+call.request.`+tt.projection+`)});`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := oneSQL(t, r)
			if u.Completeness == nil || len(u.Completeness.Blockers) > 0 || len(u.Dependencies) == 0 {
				t.Fatalf("wrong loader field projection: %+v", u.Completeness.Blockers)
			}
		})
	}
}

func TestGRPCUnknownAndStreamingFieldCollision(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "search.proto", strings.Replace(grpcProto, "string email = 1;", "string user_name=1; string userName=2;", 1))
	writeSource(t, root, "app.js", grpcSetup+`server.addService(api.fixtures.search.SearchService.service,{search:call=>call.request.userName});`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 1 || r.Handler(r.Entries[0].ID) != nil || !gapKind(r.Entries[0].Gaps, "grpc_message_unresolved") {
		t.Fatal("colliding loader fields acquired a resolved handler")
	}
}

func TestGRPCUnknownAndStreamingSharedBudget(t *testing.T) {
	for _, grpcFirst := range []bool{false, true} {
		t.Run(fmt.Sprint(grpcFirst), func(t *testing.T) {
			root := t.TempDir()
			proto := `syntax="proto3";message Request{} message Reply{} service S {`
			for i := 0; i < 128; i++ {
				proto += fmt.Sprintf("rpc M%d(Request) returns (Reply);", i)
			}
			proto += "}"
			writeSource(t, root, "search.proto", proto)
			source := grpcSetup
			for i := 0; i < 17; i++ {
				source += `server.addService(api.S.service,{});`
			}
			first, last := "a.js", "z.js"
			if !grpcFirst {
				first, last = last, first
			}
			writeSource(t, root, first, source)
			writeSource(t, root, last, "import {ApolloServer} from '@apollo/server';new ApolloServer({typeDefs:`type Query{constant:String}`,resolvers:{Query:{constant:()=>''}}});")
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != 2000 || !gapKind(r.Gaps, "grpc_registration_limit") || grpcFirst && !gapKind(r.Gaps, "graphql_registration_limit") {
				t.Fatalf("shared expansion budget: entries=%d gaps=%+v", len(r.Entries), r.Gaps)
			}
		})
	}
}
