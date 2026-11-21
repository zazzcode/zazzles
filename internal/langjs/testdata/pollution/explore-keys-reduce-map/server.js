const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function vulnerable(target, source) {
  return Object.keys(source).reduce((acc, key) => {
    if (source[key] && typeof source[key] === 'object') vulnerable(acc[key], source[key]);
    else acc[key] = source[key];
    return acc;
  }, target);
}

function guarded(target, source) {
  return Object.keys(source).reduce((acc, key) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return acc;
    if (source[key] && typeof source[key] === 'object') guarded(acc[key], source[key]);
    else acc[key] = source[key];
    return acc;
  }, target);
}

function partial(target, source) {
  return Object.keys(source).reduce((acc, key) => {
    if (key === '__proto__') return acc;
    if (source[key] && typeof source[key] === 'object') partial(acc[key], source[key]);
    else acc[key] = source[key];
    return acc;
  }, target);
}

function mapped(target, source) {
  Object.keys(source).map((key) => {
    if (source[key] && typeof source[key] === 'object') mapped(target[key], source[key]);
    else target[key] = source[key];
  });
  return target;
}

// Control: a one-level copy into a fresh accumulator.
function shallow(source) {
  return Object.keys(source).reduce((acc, key) => {
    acc[key] = source[key];
    return acc;
  }, {});
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body); res.end(); });
app.post('/mapped', (req, res) => { mapped(store, req.body); res.end(); });
app.post('/shallow', (req, res) => { res.json(shallow(req.body)); });
