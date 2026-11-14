const express = require('express');
const AdmZip = require('adm-zip');

const app = express();

app.post('/import', (req, res) => {
  const upload = req.files.archive;
  const zip = new AdmZip(upload.data);
  zip.extractAllTo('/tmp/extracted', true);
  res.send('ok');
});

app.post('/bundled', (req, res) => {
  const zip = new AdmZip('/srv/static/bundle.zip');
  zip.extractAllTo('/tmp/extracted', true);
  res.send('ok');
});
