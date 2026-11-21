const express = require('express');
const app = express();
app.use(express.json());
const store = {};
function setPath(path, value) {
  const parts = path.split('.');
  const last = parts.pop();
  const holder = parts.reduce((cursor, part) => cursor[part], store);
  holder[last] = value;
}
app.post('/a', (req, res) => { setPath(req.body.path, req.body.value); res.json({ ok: true }); });
