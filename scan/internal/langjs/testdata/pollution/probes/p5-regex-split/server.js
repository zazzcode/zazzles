const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function setPath(target, path, value) {
  const parts = path.split(/[.\[\]]+/);
  let cursor = target;
  for (let i = 0; i < parts.length - 1; i++) {
    cursor = cursor[parts[i]];
  }
  cursor[parts[parts.length - 1]] = value;
}
app.post('/a', (req, res) => { setPath(store, req.body.path, req.body.value); res.json({ ok: true }); });
