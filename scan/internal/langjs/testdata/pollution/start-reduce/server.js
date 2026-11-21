const express = require('express');
const app = express();
app.use(express.json());
const store = {};

function vulnerable(path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const cursor = parts.reduce((current, part) => current[part], store);
  cursor[last] = value;
}

function guarded(path, value) {
  const parts = path.split('.');
  if (parts.includes('__proto__') || parts.includes('constructor') || parts.includes('prototype')) return;
  const last = parts.pop();
  const cursor = parts.reduce((current, part) => current[part], store);
  cursor[last] = value;
}

function partial(path, value) {
  const parts = path.split('.');
  if (parts.includes('__proto__')) return;
  const last = parts.pop();
  const cursor = parts.reduce((current, part) => current[part], store);
  cursor[last] = value;
}

function control(path, value) {
  const parts = 'settings.theme'.split('.');
  const last = parts.pop();
  const cursor = parts.reduce((current, part) => current[part], store);
  cursor[last] = value;
}

app.post('/vulnerable', (req, res) => { vulnerable(req.body.path, req.body.value); res.end(); });

app.post('/guarded', (req, res) => { guarded(req.body.path, req.body.value); res.end(); });

app.post('/partial', (req, res) => { partial(req.body.path, req.body.value); res.end(); });

app.post('/control', (req, res) => { control(req.body.path, req.body.value); res.end(); });
