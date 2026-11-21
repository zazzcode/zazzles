const express = require('express');
const app = express();
app.use(express.json());
const store = {};

function vulnerable(path, value) {
  const parts = path.split('.');
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}

function guarded(path, value) {
  const parts = path.split('.');
  if (parts.includes('__proto__') || parts.includes('constructor') || parts.includes('prototype')) return;
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}

function partial(path, value) {
  const parts = path.split('.');
  if (parts.includes('__proto__')) return;
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}

function control(path, value) {
  const parts = 'settings.theme'.split('.');
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}

app.post('/vulnerable', (req, res) => { vulnerable(req.body.path, req.body.value); res.end(); });

app.post('/guarded', (req, res) => { guarded(req.body.path, req.body.value); res.end(); });

app.post('/partial', (req, res) => { partial(req.body.path, req.body.value); res.end(); });

app.post('/control', (req, res) => { control(req.body.path, req.body.value); res.end(); });
