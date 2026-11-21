const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function setIn(target, path, value) {
  let cursor = target;
  for (let i = 0; i < path.length - 1; i++) {
    cursor = cursor[path[i]];
  }
  cursor[path[path.length - 1]] = value;
}
app.post('/a', (req, res) => { setIn(store, req.body.path, req.body.value); res.json({ ok: true }); });
