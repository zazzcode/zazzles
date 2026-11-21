const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, path, value) {
  let cursor = target;
  for (let i = 0; i < path.length - 1; i++) {
    cursor = cursor[path[i]];
  }
  cursor[path[path.length - 1]] = value;
}

// The parts of a caller's array need not be strings: ['__proto__'] is not equal
// to '__proto__' and still names that key. The guard rejects such a part first.
function guarded(target, path, value) {
  let cursor = target;
  for (let i = 0; i < path.length - 1; i++) {
    const part = path[i];
    if (typeof part !== 'string') return;
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') return;
    cursor = cursor[part];
  }
  cursor[path[path.length - 1]] = value;
}

function partial(target, path, value) {
  let cursor = target;
  for (let i = 0; i < path.length - 1; i++) {
    const part = path[i];
    if (typeof part !== 'string') return;
    if (part === '__proto__') return;
    cursor = cursor[part];
  }
  cursor[path[path.length - 1]] = value;
}

// Control: the walked array is a constant of the function.
function fixed(target, value) {
  const path = ['settings', 'theme'];
  let cursor = target;
  for (let i = 0; i < path.length - 1; i++) {
    cursor = cursor[path[i]];
  }
  cursor[path[path.length - 1]] = value;
}

// Control: a read-only walk writes nothing.
function read(target, path) {
  let cursor = target;
  for (let i = 0; i < path.length; i++) {
    cursor = cursor[path[i]];
  }
  return cursor;
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body.path, req.body.value); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body.path, req.body.value); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body.path, req.body.value); res.end(); });
app.post('/fixed', (req, res) => { fixed(store, req.body.value); res.end(); });
app.post('/constant', (req, res) => { vulnerable(store, ['settings', 'theme'], req.body.value); res.end(); });
app.post('/read', (req, res) => { res.json(read(store, req.body.path)); });
