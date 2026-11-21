const express = require('express');
const app = express();
app.use(express.json());
const store = {};

function vulnerable(req, res) {
  const parts = req.body.path.split('.');
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = req.body.value;
  res.end();
}

function guarded(req, res) {
  const parts = req.body.path.split('.');
  if (parts.includes('__proto__') || parts.includes('constructor') || parts.includes('prototype')) return res.status(400).end();
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = req.body.value;
  res.end();
}

function partial(req, res) {
  const parts = req.body.path.split('.');
  if (parts.includes('__proto__')) return res.status(400).end();
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = req.body.value;
  res.end();
}

function control(req, res) {
  const parts = 'settings.theme'.split('.');
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = req.body.value;
  res.end();
}

app.post('/vulnerable', vulnerable);

app.post('/guarded', guarded);

app.post('/partial', partial);

app.post('/control', control);
