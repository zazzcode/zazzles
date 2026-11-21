const express = require('express');
const app = express();
app.use(express.json());

// user[address][city] -> ['user', 'address', 'city'], collected by an exec loop.
function vulnerable(source) {
  const out = {};
  for (const flat in source) {
    const pattern = /([^\[\]]+)/g;
    const parts = [];
    let match;
    while ((match = pattern.exec(flat)) !== null) {
      parts.push(match[1]);
    }
    let cursor = out;
    for (let i = 0; i < parts.length - 1; i++) {
      cursor = cursor[parts[i]];
    }
    cursor[parts[parts.length - 1]] = source[flat];
  }
  return out;
}

// The same keys taken with one global match.
function matched(source) {
  const out = {};
  for (const flat in source) {
    const parts = flat.match(/[^\[\]]+/g);
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
    const parts = flat.match(/[^\[\]]+/g);
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
    const parts = flat.match(/[^\[\]]+/g);
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

app.post('/vulnerable', (req, res) => { res.json(vulnerable(req.body)); });
app.post('/matched', (req, res) => { res.json(matched(req.body)); });
app.post('/guarded', (req, res) => { res.json(guarded(req.body)); });
app.post('/partial', (req, res) => { res.json(partial(req.body)); });
