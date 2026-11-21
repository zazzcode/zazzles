package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
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
