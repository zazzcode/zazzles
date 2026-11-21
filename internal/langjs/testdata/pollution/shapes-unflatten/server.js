const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(source) {
  const out = {};
  for (const flat in source) {
    const parts = flat.split('.');
    let cursor = out;
    for (let i = 0; i < parts.length - 1; i++) {
      cursor = cursor[parts[i]];
    }
    cursor[parts[parts.length - 1]] = source[flat];
  }
  return out;
}

function guarded(source) {
  const out = {};
  for (const flat in source) {
    const parts = flat.split('.');
    let cursor = out;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (part === '__proto__' || part === 'constructor' || part === 'prototype') return out;
      cursor = cursor[part];
    }
    cursor[parts[parts.length - 1]] = source[flat];
  }
  return out;
}

function partial(source) {
  const out = {};
  for (const flat in source) {
    const parts = flat.split('.');
    let cursor = out;
    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (part === '__proto__') return out;
      cursor = cursor[part];
    }
    cursor[parts[parts.length - 1]] = source[flat];
  }
  return out;
}

// Control: each key is split but only its first part is written, one level deep.
function firstLevel(source) {
  const out = {};
  for (const flat in source) {
    const parts = flat.split('.');
    out[parts[0]] = source[flat];
  }
  return out;
}

app.post('/vulnerable', (req, res) => { res.json(vulnerable(req.body)); });
app.post('/guarded', (req, res) => { res.json(guarded(req.body)); });
app.post('/partial', (req, res) => { res.json(partial(req.body)); });
app.post('/first-level', (req, res) => { res.json(firstLevel(req.body)); });
