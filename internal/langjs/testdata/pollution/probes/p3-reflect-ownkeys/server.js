const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function merge(target, source) {
  Reflect.ownKeys(source).forEach((key) => {
    if (source[key] && typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  });
}
app.post('/a', (req, res) => { merge(store, req.body); res.json({ ok: true }); });
