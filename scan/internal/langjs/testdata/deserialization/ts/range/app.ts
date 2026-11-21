import express from 'express';
import * as yaml from 'js-yaml';
import YAML from 'js-yaml';
import { load } from 'js-yaml';
import { load as parse } from 'js-yaml';
import fs from 'fs';

const app = express();

app.post('/js-u1', (req, res) => {
  return res.json(yaml.load(req.body.y)); // JS-U1
});
