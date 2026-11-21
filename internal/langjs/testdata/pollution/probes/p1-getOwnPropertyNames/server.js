const express = require('express');
const app = express();
const store = {};
app.use(express.json());

function merge(target, source, options = {}) {
  for (const key of Object.getOwnPropertyNames(source)) {
    const src = Object.getOwnPropertyDescriptor(source, key);
    let srcVal = src.value;
    let trgVal = target[key];
    if (srcVal && typeof srcVal === 'object') {
      if (options.deep) {
        if (!trgVal) trgVal = target[key] = {};
        merge(trgVal, srcVal, options);
        continue;
      }
    }
    target[key] = srcVal;
  }
  return target;
}
app.post('/a', (req, res) => { merge(store, req.body, { deep: true }); res.json({ ok: true }); });
