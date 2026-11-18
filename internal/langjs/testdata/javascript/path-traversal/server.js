const express = require('express');
const fs = require('fs');
const { readFileSync, writeFile: save } = require('node:fs');
const fsPromises = require('fs').promises;
const path = require('path');

const app = express();
const BASE = path.join(__dirname, 'public');

// vulnerable: CommonJS bindings of the same verified operations
app.get('/cjs/read', (req, res) => {
  fs.readFile(path.join(BASE, req.query.name), (err, data) => res.send(data));
});

app.get('/cjs/destructured', (req, res) => {
  res.send(readFileSync(path.join(BASE, req.query.name)));
});

app.post('/cjs/aliased-write', (req, res) => {
  save(path.join(BASE, req.body.file), req.body.text, () => res.end());
});

app.get('/cjs/promises', async (req, res) => {
  res.send(await fsPromises.readFile(path.join(BASE, req.query.name)));
});

// protected: separator-bounded prefix check on the resolved value
app.get('/cjs/guarded', (req, res) => {
  const target = path.resolve(BASE, req.query.name);
  if (!target.startsWith(BASE + path.sep)) {
    return res.sendStatus(403);
  }
  res.send(fs.readFileSync(target));
});

// no candidate: a local module named fs, never the core module
const local = require('./local-fs');
app.get('/cjs/local-module', (req, res) => {
  res.send(local.readFileSync(req.query.name));
});

// no candidate: reassigned binding is not the verified core module
let reassigned = require('fs');
reassigned = { readFileSync: (p) => p };
app.get('/cjs/reassigned', (req, res) => {
  res.send(reassigned.readFileSync(req.query.name));
});
