import express, { Request, Response } from 'express';
import fs from 'fs';
import * as fsp from 'node:fs/promises';
import path from 'path';
import { sanitizeName } from './sanitize';

const app = express();
const ROOT = path.resolve(__dirname, '../uploads');
const ALLOWED = new Set(['report.txt', 'notes.txt']);
const NAMES = ['report.txt', 'notes.txt'];

// ---- vulnerable: request value reaches the path operand with no enforced containment ----

app.get('/v/join-read', (req: Request, res: Response) => {
  const filename: string = req.query.filename as string;
  const filePath: string = path.join(__dirname, '../uploads', filename);
  fs.readFile(filePath, 'utf8', (err: NodeJS.ErrnoException | null, data: string) => {
    if (err) {
      res.status(404).json({ error: 'File not found' });
    } else {
      res.send(data);
    }
  });
});

app.get('/v/resolve-sync', (req: Request, res: Response) => {
  res.send(fs.readFileSync(path.resolve(ROOT, req.query.f as string), 'utf8'));
});

app.post('/v/write', (req: Request, res: Response) => {
  fs.writeFile(path.join(ROOT, req.body.name), req.body.data, (err) => res.json({ ok: !err }));
});

app.get('/v/promises', async (req: Request, res: Response) => {
  res.send(await fsp.readFile(path.join(ROOT, String(req.query.f))));
});

app.get('/v/normalize-only', (req: Request, res: Response) => {
  res.send(fs.readFileSync(path.normalize(req.query.f as string)));
});

app.get('/v/direct', (req: Request, res: Response) => {
  fs.readFile(req.query.f as string, (err, data) => res.send(data));
});

app.get('/v/try-catch', (req: Request, res: Response) => {
  try {
    res.send(fs.readFileSync(path.join(ROOT, req.query.f as string)));
  } catch (e) {
    res.status(404).end();
  }
});

app.get('/v/blacklist', (req: Request, res: Response) => {
  const name = req.query.f as string;
  if (name.includes('..')) {
    return res.status(400).end();
  }
  res.send(fs.readFileSync(path.join(ROOT, decodeURIComponent(name))));
});

app.get('/v/reassigned', (req: Request, res: Response) => {
  let name = req.query.f as string;
  if (!ALLOWED.has(name)) {
    return res.status(404).end();
  }
  name = req.query.g as string;
  res.send(fs.readFileSync(path.join(ROOT, name)));
});

app.get('/v/sibling-branch', (req: Request, res: Response) => {
  const name = req.query.f as string;
  if (req.query.mode === 'strict') {
    if (!ALLOWED.has(name)) {
      return res.status(404).end();
    }
  }
  res.send(fs.readFileSync(path.join(ROOT, name)));
});

function load(name: string) {
  return fs.readFileSync(path.join(ROOT, name), 'utf8');
}
app.get('/v/helper', (req: Request, res: Response) => {
  res.send(load(req.query.f as string));
});

// ---- protected: an enforced, source-backed containment on the same value ----

app.get('/p/allowlist', (req: Request, res: Response) => {
  const name = req.query.f as string;
  if (!ALLOWED.has(name)) {
    return res.status(404).end();
  }
  res.send(fs.readFileSync(path.join(ROOT, name)));
});

app.get('/p/allowlist-array', (req: Request, res: Response) => {
  const name = req.query.f as string;
  if (!NAMES.includes(name)) {
    return res.status(404).end();
  }
  res.send(fs.readFileSync(path.join(ROOT, name)));
});

app.get('/p/prefix-boundary', (req: Request, res: Response) => {
  const full = path.resolve(ROOT, req.query.f as string);
  if (!full.startsWith(ROOT + path.sep)) {
    return res.status(403).end();
  }
  res.send(fs.readFileSync(full));
});

app.get('/p/relative', (req: Request, res: Response) => {
  const full = path.resolve(ROOT, req.query.f as string);
  const rel = path.relative(ROOT, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return res.status(403).end();
  }
  res.send(fs.readFileSync(full));
});

app.get('/p/realpath', (req: Request, res: Response) => {
  const full = fs.realpathSync(path.resolve(ROOT, req.query.f as string));
  const rel = path.relative(ROOT, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return res.status(403).end();
  }
  res.send(fs.readFileSync(full));
});

function readChecked(file: string) {
  return fs.readFileSync(path.join(ROOT, file), 'utf8');
}
app.get('/p/helper-guard', (req: Request, res: Response) => {
  const name = req.query.f as string;
  if (!ALLOWED.has(name)) {
    return res.status(404).end();
  }
  res.send(readChecked(name));
});

function readEither(file: string) {
  return fs.readFileSync(path.join(ROOT, file), 'utf8');
}
app.get('/u/helper-two-callers', (req: Request, res: Response) => {
  const name = req.query.f as string;
  if (req.query.mode === 'strict') {
    if (!ALLOWED.has(name)) {
      return res.status(404).end();
    }
    return res.send(readEither(name));
  }
  res.send(readEither(name));
});

// ---- unknown: control semantics are not established ----

app.get('/u/prefix-bare', (req: Request, res: Response) => {
  const full = path.resolve(ROOT, req.query.f as string);
  if (!full.startsWith(ROOT)) {
    return res.status(403).end();
  }
  res.send(fs.readFileSync(full));
});

app.get('/u/missing-helper', (req: Request, res: Response) => {
  const safe = sanitizeName(req.query.f as string);
  res.send(fs.readFileSync(path.join(ROOT, safe)));
});

app.get('/u/basename', (req: Request, res: Response) => {
  res.send(fs.readFileSync(path.join(ROOT, path.basename(req.query.f as string))));
});

// ---- no candidate: no request value in the path operand, or no verified binding ----

app.get('/n/constant', (req: Request, res: Response) => {
  res.send(fs.readFileSync(path.join(ROOT, 'report.txt')));
});

app.post('/n/content-only', (req: Request, res: Response) => {
  fs.writeFileSync(path.join(ROOT, 'fixed.txt'), req.body.data);
  res.send('ok');
});

app.get('/n/shadowed-param', (req: Request, res: Response) => {
  const read = (fs: { readFileSync: (p: string) => string }) => fs.readFileSync(req.query.f as string);
  res.send(read({ readFileSync: (p: string) => p }));
});

app.get('/n/fake-object', (req: Request, res: Response) => {
  const fake = { readFileSync: (p: string) => p };
  res.send(fake.readFileSync(req.query.f as string));
});

// ---- request URL path as the source (req.path is not a modeled request field elsewhere) ----

app.use('/static', (req: Request, res: Response, next) => {
  const filePath = path.resolve('public', path.normalize(req.path).replace(/^[\\/]+/, ''));
  if (!filePath.startsWith(path.resolve('public'))) {
    return res.status(403).end();
  }
  fs.readFile(filePath, 'utf8', (err, data) => (err ? next() : res.send(data)));
});

app.get('/v/url', (req: Request, res: Response) => {
  res.send(fs.readFileSync(path.join(ROOT, req.originalUrl)));
});

// ---- Express file-send wrappers ----

app.get('/v/send-file', (req: Request, res: Response) => {
  res.sendFile(path.resolve(ROOT, req.query.f as string));
});

app.get('/v/download', (req: Request, res: Response) => {
  res.download(path.join(ROOT, req.query.f as string), 'report.txt');
});

app.get('/p/send-root', (req: Request, res: Response) => {
  res.sendFile(req.query.f as string, { root: ROOT });
});

app.get('/v/send-dynamic-root', (req: Request, res: Response) => {
  res.sendFile(req.query.f as string, { root: req.query.r as string });
});

function sendChecked(file: string, res: Response) {
  res.sendFile(path.resolve(ROOT, file));
}
app.get('/u/send-separator/:file', (req: Request, res: Response) => {
  const file = req.params.file;
  if (file.includes('/')) {
    return res.status(403).end();
  }
  sendChecked(file, res);
});

app.get('/n/send-constant', (req: Request, res: Response) => {
  res.sendFile(path.resolve(ROOT, 'report.txt'));
});

// ---- streams, append and delete ----

app.get('/v/stream', (req: Request, res: Response) => {
  fs.createReadStream(path.join(ROOT, req.query.f as string)).pipe(res);
});

app.post('/v/append', (req: Request, res: Response) => {
  fs.appendFileSync(path.join(ROOT, req.body.name), req.body.line);
  res.end();
});

app.delete('/v/unlink', (req: Request, res: Response) => {
  fs.unlinkSync(path.join(ROOT, req.body.name));
  res.end();
});
