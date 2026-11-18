package langpy

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func TestPhase2PythonFileAPIs(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.py", `
from fastapi import FastAPI, UploadFile, File
from fastapi.responses import FileResponse
import shutil, tarfile, io
app = FastAPI()

@app.get('/file')
def file(name: str):
    return FileResponse(f'/data/{name}')

@app.post('/upload')
async def upload(f: UploadFile = File(...)):
    open('/tmp/' + f.filename, 'wb').write(await f.read())
    return 'ok'

@app.post('/shutil')
def copy_it(name: str, dest: str):
    shutil.copy('/data/' + name, '/out/' + dest)
    return 'ok'

@app.post('/tar')
def extract(name: str):
    tf = tarfile.open('/archives/' + name)
    tf.extractall('/tmp/out')
    return 'ok'

@app.post('/tar-filter')
def extract_filtered(name: str):
    tf = tarfile.open('/archives/' + name)
    tf.extractall('/tmp/out', filter='data')
    return 'ok'
`)
	r, err := Analyze(root, "app.py")
	if err != nil {
		t.Fatal(err)
	}
	uses := pathUses(r)
	if u, ok := uses["/file"]; !ok || u.Path.ContractID != analysispacks.StarletteFileContract {
		t.Fatalf("FileResponse: %+v", uses["/file"])
	}
	u, ok := uses["/upload"]
	if !ok || u.APIModel == nil || u.APIModel.ID != analysispacks.PythonOpenContract {
		t.Fatalf("UploadFile open path: %+v", uses["/upload"])
	}
	foundFilename := false
	for _, d := range u.Dependencies {
		for _, tr := range d.Transfers {
			if strings.Contains(tr.Text, "filename") {
				foundFilename = true
			}
		}
	}
	if !foundFilename {
		t.Fatalf("UploadFile.filename transfer missing: %+v", u.Dependencies)
	}
	sh := uses["/shutil"]
	if sh.Path.ContractID != analysispacks.PythonShutilContract {
		t.Fatalf("shutil contract: %+v", sh.Path)
	}
	destFlow := false
	for _, p := range sh.Path.Paths {
		if p.Operand == analysis.PathSlotDestination {
			destFlow = true
		}
	}
	if !destFlow {
		t.Fatalf("shutil missing destination flow: %+v", sh.Path)
	}
	tar := uses["/tar"]
	if tar.Path.ContractID != analysispacks.PythonTarExtractContract {
		t.Fatalf("extractall contract: %+v", tar.Path)
	}
	if tar.Path.Extractor == nil || tar.Path.Extractor.Library != "tarfile" {
		t.Fatalf("extractall filter facts: %+v", tar.Path.Extractor)
	}
	if !gapKind(tar.Gaps, "tar_filter_unresolved") {
		t.Fatalf("absent filter should be unresolved: %+v", tar.Gaps)
	}
	filtered := uses["/tar-filter"]
	if filtered.Path.Extractor == nil || filtered.Path.Extractor.Declared != "filter=data" {
		t.Fatalf("explicit filter: %+v", filtered.Path.Extractor)
	}
}
