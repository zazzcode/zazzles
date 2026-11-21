const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, source) {
  for (const key in source) {
    const srcVal = source[key];
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (!trgVal) trgVal = target[key] = {};
      vulnerable(trgVal, srcVal);
      continue;
    }
    target[key] = srcVal;
  }
}

function guarded(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const srcVal = source[key];
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (!trgVal) trgVal = target[key] = {};
      guarded(trgVal, srcVal);
      continue;
    }
    target[key] = srcVal;
  }
}

function partial(target, source) {
  for (const key in source) {
    if (key === '__proto__') continue;
    const srcVal = source[key];
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (!trgVal) trgVal = target[key] = {};
      partial(trgVal, srcVal);
      continue;
    }
    target[key] = srcVal;
  }
}

// Control: the local is replaced by a fresh object, so the recursion never
// receives the looked-up slot.
function fresh(target, source) {
  for (const key in source) {
    const srcVal = source[key];
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      trgVal = {};
      fresh(trgVal, srcVal);
      target[key] = trgVal;
      continue;
    }
    target[key] = srcVal;
  }
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body); res.end(); });
app.post('/fresh', (req, res) => { fresh(store, req.body); res.end(); });
