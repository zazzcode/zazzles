const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function merge(target, source) {
  for (const key in source) {
    const srcVal = source[key];
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (!trgVal) trgVal = target[key] = {};
      merge(trgVal, srcVal);
      continue;
    }
    target[key] = srcVal;
  }
}
app.post('/a', (req, res) => { merge(store, req.body); res.json({ ok: true }); });
