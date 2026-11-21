const express = require('express');
const app = express();
app.use(express.json());
const store = {};
function setPath(target, path, value) {
  let cursor = target;
  const parts = path.split('.');
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}
app.post('/a', (req, res) => { setPath(store, req.body.path, req.body.value); res.json({ ok: true }); });
