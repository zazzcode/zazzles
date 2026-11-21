const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function setPath(target, path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const holder = parts.reduce((cursor, part) => cursor[part], target);
  holder[last] = value;
}
app.post('/a', (req, res) => { setPath(store, req.body.path, req.body.value); res.json({ ok: true }); });
