import { readFileSync } from 'fs';
import path from 'path';

const ROOT = path.resolve('reports');
const ALLOWED = new Set(['daily.txt', 'weekly.txt']);

export function report(parent, args) {
  return readFileSync(path.join(ROOT, args.name), 'utf8');
}
export function listed(parent, args) {
  if (!ALLOWED.has(args.name)) { throw new Error('rejected'); }
  return readFileSync(path.join(ROOT, args.name), 'utf8');
}
export function fixed(parent, args) {
  return readFileSync(path.join(ROOT, 'daily.txt'), 'utf8');
}
