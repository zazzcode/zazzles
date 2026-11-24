package langjs

import (
	"path/filepath"
	"reflect"
	"sort"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

type uploadWant struct {
	line        int
	entry       string
	operation   string
	contract    string
	stored      string
	extension   string
	served      string
	destination string
	controls    string // control kinds, comma separated, in recorded order
}

// TestExpressUpload covers D-10: a multer middleware with memory storage and
// with disk storage on single, array, fields and any records one upload
// candidate on its route; the destination is served when an express.static or
// serve-index mount covers it; a route with no multer middleware, and one whose
// middleware accepts text fields only, record nothing.
func TestExpressUpload(t *testing.T) {
	memory, disk := "multer.memoryStorage", "multer.diskStorage"
	inMemory, onDisk := analysispacks.NodeMulterMemory, analysispacks.NodeMulterDisk
	declared, allowList := analysis.UploadClientDeclaredType, analysis.UploadExtensionAllowList
	for _, tt := range []struct {
		name string
		dir  string
		file string
		want []uploadWant
	}{
		{"primary", "upload-express/primary", "server.ts", []uploadWant{
			{39, "POST /memory/one", memory + ".single", inMemory, "unknown", "unknown", "unknown", "", ""},
			{40, "POST /memory/many", memory + ".array", inMemory, "unknown", "unknown", "unknown", "", ""},
			{41, "POST /memory/named", memory + ".fields", inMemory, "unknown", "unknown", "unknown", "", ""},
			{42, "POST /memory/all", memory + ".any", inMemory, "unknown", "unknown", "unknown", "", ""},
			{43, "POST /disk/one", disk + ".single", onDisk, "client", "client", "yes", "public/pictures", declared},
			{44, "POST /disk/many", disk + ".array", onDisk, "client", "client", "yes", "public/pictures", declared},
			{45, "POST /disk/named", disk + ".fields", onDisk, "client", "client", "yes", "public/pictures", declared},
			{46, "POST /disk/all", disk + ".any", onDisk, "client", "client", "yes", "public/pictures", declared},
			{47, "POST /side", disk + ".single", onDisk, "server_generated", "fixed", "no", "private/incoming", ""},
		}},
		{"transfer", "upload-express/transfer", "index.js", []uploadWant{
			{33, "PUT /held/one", memory + ".single", inMemory, "unknown", "unknown", "unknown", "", ""},
			{34, "PUT /held/many", memory + ".array", inMemory, "unknown", "unknown", "unknown", "", ""},
			{35, "PUT /held/named", memory + ".fields", inMemory, "unknown", "unknown", "unknown", "", ""},
			{36, "PUT /held/all", memory + ".any", inMemory, "unknown", "unknown", "unknown", "", ""},
			{37, "PUT /kept/one", disk + ".single", onDisk, "mixed", "allow_listed", "yes", "shared/inbox", allowList},
			{38, "PUT /kept/many", disk + ".array", onDisk, "mixed", "allow_listed", "yes", "shared/inbox", allowList},
			{39, "PUT /kept/named", disk + ".fields", onDisk, "mixed", "allow_listed", "yes", "shared/inbox", allowList},
			{40, "PUT /kept/all", disk + ".any", onDisk, "mixed", "allow_listed", "yes", "shared/inbox", allowList},
			// The mount is given relative to the module and the destination
			// relative to the working directory, so coverage is not established.
			{41, "PUT /dropped", disk + ".single", onDisk, "server_generated", "fixed", "unknown", "spool", ""},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			var got []uploadWant
			for _, u := range report.Uses {
				if u.Kind != "file_upload_candidate" {
					continue
				}
				f, line := u.Upload, u.Sink.Span.StartLine
				if f == nil || u.Sink.Span.File != tt.file {
					t.Fatalf("upload use at %s:%d has no facts or the wrong file", u.Sink.Span.File, line)
				}
				if err := f.Validate(len(u.Dependencies), len(u.Context)); err != nil {
					t.Fatalf("line %d: %v", line, err)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("line %d: no component selection: %+v", line, u.Components)
				}
				c := u.Completeness
				if c == nil || c.ClaimKind != "upload" || len(c.Blockers) != 0 {
					t.Fatalf("line %d: completeness %+v", line, c)
				}
				if u.APIModel == nil || u.APIModel.ID != f.ContractID {
					t.Fatalf("line %d: contract %+v does not match %s", line, u.APIModel, f.ContractID)
				}
				for _, role := range append(append([]string{}, c.Required...), u.Components.Required...) {
					if len(c.Evidence[role]) == 0 {
						t.Errorf("line %d: no evidence for role %s", line, role)
					}
				}
				if u.InputFacts == nil || len(u.InputFacts.Values) != len(u.Dependencies) || u.InputFacts.Values[0].Origin != "http.upload_content" {
					t.Errorf("line %d: input facts %+v", line, u.InputFacts)
				}
				if f.Paths[0].Operand != "upload_content" || u.Dependencies[0].SinkSlot != "upload_content" {
					t.Errorf("line %d: first dependency is not the uploaded content", line)
				}
				entry, controls := "", ""
				for _, e := range report.Entries {
					if e.ID == u.EntryID {
						entry = e.Name
					}
				}
				for i, k := range f.TypeControls {
					if i > 0 {
						controls += ","
					}
					controls += k.Kind
					if k.ClientControlled != (k.Kind == declared) {
						t.Errorf("line %d: control %s client_controlled = %v", line, k.Kind, k.ClientControlled)
					}
				}
				got = append(got, uploadWant{line, entry, f.Operation, f.ContractID, f.StoredName, f.ExtensionOrigin, f.DestinationServed, f.Destination, controls})
			}
			sort.Slice(got, func(i, j int) bool { return got[i].line < got[j].line })
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("upload candidates:\n got  %+v\n want %+v", got, tt.want)
			}
		})
	}
}
