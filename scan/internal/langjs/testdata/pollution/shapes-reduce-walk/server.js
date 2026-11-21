const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const holder = parts.reduce((cursor, part) => cursor[part], target);
  holder[last] = value;
}

function guarded(target, path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const holder = parts.reduce((cursor, part) => {
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') return cursor;
    return cursor[part];
  }, target);
  holder[last] = value;
}

function partial(target, path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const holder = parts.reduce((cursor, part) => {
    if (part === '__proto__') return cursor;
    return cursor[part];
  }, target);
  holder[last] = value;
}

// Control: the walk result is only returned.
function read(target, path) {
  return path.split('.').reduce((cursor, part) => cursor[part], target);
}

function readParts(target, path) {
  const parts = path.split('.');
  const found = parts.reduce((cursor, part) => cursor[part], target);
  return found;
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body.path, req.body.value); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body.path, req.body.value); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body.path, req.body.value); res.end(); });
app.post('/read', (req, res) => { res.json(read(store, req.body.path)); });
app.post('/read-parts', (req, res) => { res.json(readParts(store, req.body.path)); });
