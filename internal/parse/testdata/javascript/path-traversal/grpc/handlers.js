import fs from 'fs';
import path from 'path';

const ROOT = path.resolve('reports');
export function fetch(call, callback) {
  fs.readFile(path.join(ROOT, call.request.name), 'utf8', function (err, data) { callback(null, { body: data }); });
}
export function fixed(call, callback) {
  fs.readFile(path.join(ROOT, 'daily.txt'), 'utf8', function (err, data) { callback(null, { body: data }); });
}
