package parse

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func TestPhase2NodeFSOps(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `
const express=require('express');
const fs=require('fs');
const fsp=require('fs/promises');
const path=require('path');
const app=express();
const ROOT='/tmp/data';
app.get('/open',(req,res)=>{fs.open(path.join(ROOT,req.query.f),'r',(e,fd)=>{res.end(String(fd))})});
app.get('/open-p',async(req,res)=>{const h=await fsp.open(path.join(ROOT,req.query.f));res.end()});
app.post('/copy',(req,res)=>{fs.copyFile(path.join(ROOT,'a'),path.join(ROOT,req.body.dest),(e)=>res.end())});
app.post('/copy-src',(req,res)=>{fs.copyFileSync(path.join(ROOT,req.body.src),path.join(ROOT,'out'))});
app.post('/rename',async(req,res)=>{await fsp.rename(path.join(ROOT,req.body.src),path.join(ROOT,req.body.dest));res.end()});
app.post('/open-const',(req,res)=>{fs.open('/tmp/fixed','r',()=>res.end())});
`)
	r, err := Analyze(root, "server.js")
	if err != nil {
		t.Fatal(err)
	}
	uses := pathUses(r)
	for _, route := range []string{"/open", "/open-p", "/copy", "/copy-src", "/rename"} {
		if _, ok := uses[route]; !ok {
			t.Fatalf("missing path candidate for %s", route)
		}
	}
	if _, ok := uses["/open-const"]; ok {
		t.Fatal("constant open must not be a path candidate")
	}
	copyUse := uses["/copy"]
	if copyUse.Path.ContractID != analysispacks.NodeFSContract || copyUse.Path.Operation != "fs.copyFile" {
		t.Fatalf("copy contract/op: %+v", copyUse.Path)
	}
	foundDest := false
	for _, o := range copyUse.Path.Operands {
		if o.Slot == analysis.PathSlotDestination {
			foundDest = true
			if len(o.Dependencies) == 0 {
				t.Fatal("destination lacks request deps")
			}
		}
	}
	if !foundDest {
		t.Fatal("copyFile missing destination slot")
	}
	// Dual-path independence: rename has request on both slots.
	rename := uses["/rename"]
	slots := map[string]bool{}
	for _, p := range rename.Path.Paths {
		slots[p.Operand] = true
	}
	if !slots[analysis.PathSlotFile] || !slots[analysis.PathSlotDestination] {
		t.Fatalf("rename flows slots=%v", slots)
	}
}

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
