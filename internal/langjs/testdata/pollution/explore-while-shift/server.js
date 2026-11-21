const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  while (parts.length > 1) {
    const part = parts.shift();
    cursor = cursor[part];
  }
  cursor[parts[0]] = value;
}

function guarded(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  while (parts.length > 1) {
    const part = parts.shift();
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') return;
    cursor = cursor[part];
  }
  cursor[parts.shift()] = value;
}

function partial(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  while (parts.length > 1) {
    const part = parts.shift();
    if (part === '__proto__') return;
    cursor = cursor[part];
  }
  cursor[parts[0]] = value;
}

// The last part is taken first and the rest is consumed to empty.
function lastFirst(target, path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  let cursor = target;
  while (parts.length) {
    cursor = cursor[parts.shift()];
  }
  cursor[last] = value;
}

// Control: a read-only walk writes nothing.
function read(target, path) {
  const parts = path.split('.');
  let cursor = target;
  while (parts.length) cursor = cursor[parts.shift()];
  return cursor;
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body.path, req.body.value); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body.path, req.body.value); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body.path, req.body.value); res.end(); });
app.post('/last-first', (req, res) => { lastFirst(store, req.body.path, req.body.value); res.end(); });
app.post('/read', (req, res) => { res.json(read(store, req.body.path)); });
