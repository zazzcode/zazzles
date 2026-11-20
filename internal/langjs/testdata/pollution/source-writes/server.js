const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  }
}

function partial(target, source) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__') continue;
    if (source[key] && typeof source[key] === 'object') partial(target[key], source[key]);
    else target[key] = source[key];
  }
}

function guarded(target, source) {
  for (const [key, child] of Object.entries(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (child && typeof child === 'object') guarded(target[key], child);
    else target[key] = child;
  }
}

function own(target, source) {
  for (const key in source) {
    if (!Object.hasOwn(target, key)) continue;
    if (source[key] && typeof source[key] === 'object') own(target[key], source[key]);
    else target[key] = source[key];
  }
}

function walk(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    cursor = cursor[part];
  }
  cursor[parts[parts.length - 1]] = value;
}

app.post('/merge', (req, res) => { merge({}, req.body.settings); res.end(); });
app.post('/partial', (req, res) => { partial({}, req.body.settings); res.end(); });
app.post('/guarded', (req, res) => { guarded({}, req.body.settings); res.end(); });
app.post('/own', (req, res) => { own({}, req.body.settings); res.end(); });
app.post('/walk', (req, res) => { walk(store, req.body.path, req.body.value); res.end(); });
app.post('/nested', (req, res) => { store[req.body.a][req.body.b] = req.body.v; res.end(); });
app.post('/null', (req, res) => { Object.create(null)[req.body.a][req.body.b] = req.body.v; res.end(); });
app.post('/scalar/:name', (req, res) => { merge({}, req.params.name); res.end(); });
app.post('/shallow', (req, res) => {
  Object.assign({}, req.body);
  const settings = { ...req.body };
  JSON.parse(req.body.text);
  settings[req.body.key] = req.body.value;
  res.end();
});
