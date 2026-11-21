const express = require('express');
const app = express();
const store = {};
app.use(express.json());

// A test on the whole path that does not name a prototype key is no key guard.
function vulnerable(target, path, value) {
  if (path.includes('..')) return;
  const parts = path.split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function guarded(target, path, value) {
  if (path.includes('__proto__') || path.includes('constructor') || path.includes('prototype')) return;
  const parts = path.split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function partial(target, path, value) {
  if (path.includes('__proto__')) return;
  const parts = path.split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function indexed(target, path, value) {
  if (path.indexOf('__proto__') !== -1 || path.indexOf('constructor') !== -1 || path.indexOf('prototype') !== -1) {
    throw new Error('unsafe path');
  }
  const parts = path.split('.');
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}

function enclosed(target, path, value) {
  if (!path.includes('__proto__') && !path.includes('constructor') && !path.includes('prototype')) {
    const parts = path.split('.');
    let cursor = target;
    for (let i = 0; i < parts.length - 1; i++) {
      cursor = cursor[parts[i]];
    }
    cursor[parts[parts.length - 1]] = value;
  }
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body.path, req.body.value); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body.path, req.body.value); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body.path, req.body.value); res.end(); });
app.post('/indexed', (req, res) => { indexed(store, req.body.path, req.body.value); res.end(); });
app.post('/enclosed', (req, res) => { enclosed(store, req.body.path, req.body.value); res.end(); });
