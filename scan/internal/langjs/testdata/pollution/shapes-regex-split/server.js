const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, path, value) {
  const parts = path.split(/[.\[\]]+/);
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function guarded(target, path, value) {
  const parts = path.split(/[.\[\]]+/);
  let cursor = target;
  for (const part of parts.slice(0, -1)) {
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') return;
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
}

function partial(target, path, value) {
  const parts = path.split(/[.\[\]]+/);
  let cursor = target;
  for (const part of parts.slice(0, -1)) {
    if (part === '__proto__') return;
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
}

// Control: a read-only walk writes nothing.
function read(target, path) {
  const parts = path.split(/[.\[\]]+/);
  let cursor = target;
  for (const part of parts) cursor = cursor[part];
  return cursor;
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body.path, req.body.value); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body.path, req.body.value); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body.path, req.body.value); res.end(); });
app.post('/read', (req, res) => { res.json(read(store, req.body.path)); });
