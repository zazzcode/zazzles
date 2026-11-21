const express = require('express');
const app = express();
const store = {};
app.use(express.json());
const { shadowedReflect, shadowedObject } = require('./shadowed');

function vulnerable(target, source) {
  Reflect.ownKeys(source).forEach((key) => {
    if (source[key] && typeof source[key] === 'object') vulnerable(target[key], source[key]);
    else target[key] = source[key];
  });
}

function guarded(target, source) {
  Reflect.ownKeys(source).forEach((key) => {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
    if (source[key] && typeof source[key] === 'object') guarded(target[key], source[key]);
    else target[key] = source[key];
  });
}

function partial(target, source) {
  Reflect.ownKeys(source).forEach((key) => {
    if (key === '__proto__') return;
    if (source[key] && typeof source[key] === 'object') partial(target[key], source[key]);
    else target[key] = source[key];
  });
}

app.post('/vulnerable', (req, res) => { vulnerable(store, req.body); res.end(); });
app.post('/guarded', (req, res) => { guarded(store, req.body); res.end(); });
app.post('/partial', (req, res) => { partial(store, req.body); res.end(); });
app.post('/shadowed-reflect', (req, res) => { shadowedReflect(store, req.body); res.end(); });
app.post('/shadowed-object', (req, res) => { shadowedObject(store, req.body); res.end(); });
