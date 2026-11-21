const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, source, options = {}) {
  for (const key of Object.getOwnPropertyNames(source)) {
    const src = Object.getOwnPropertyDescriptor(source, key);
    let srcVal = src.value;
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (options.deep) {
        if (!trgVal) trgVal = target[key] = {};
        vulnerable(trgVal, srcVal, options);
        continue;
      }
      if (options.clone) srcVal = vulnerable({}, srcVal, options);
    }
    target[key] = srcVal;
  }
  return target;
}

function guarded(target, source, options = {}) {
  for (const key of Object.getOwnPropertyNames(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    const srcVal = Object.getOwnPropertyDescriptor(source, key).value;
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (options.deep) {
        if (!trgVal) trgVal = target[key] = {};
        guarded(trgVal, srcVal, options);
        continue;
      }
    }
    target[key] = srcVal;
  }
  return target;
}

function partial(target, source, options = {}) {
  for (const key of Object.getOwnPropertyNames(source)) {
    if (key === '__proto__') continue;
    const srcVal = Object.getOwnPropertyDescriptor(source, key).value;
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (options.deep) {
        if (!trgVal) trgVal = target[key] = {};
        partial(trgVal, srcVal, options);
        continue;
      }
    }
    target[key] = srcVal;
  }
  return target;
}

// Control: a one-level copy changes only its own target.
function shallow(target, source) {
  for (const key of Object.getOwnPropertyNames(source)) {
    target[key] = Object.getOwnPropertyDescriptor(source, key).value;
  }
  return target;
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body, { deep: true }); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body, { deep: true }); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body, { deep: true }); res.end(); });
app.post('/shallow', (req, res) => { shallow({}, req.body); res.end(); });
