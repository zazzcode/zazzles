const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function unflatten(source) {
  const out = {};
  for (const flat in source) {
    const parts = flat.split('.');
    let cursor = out;
    for (let i = 0; i < parts.length - 1; i++) {
      cursor = cursor[parts[i]];
    }
    cursor[parts[parts.length - 1]] = source[flat];
  }
  return out;
}
app.post('/a', (req, res) => { res.json(unflatten(req.body)); });
