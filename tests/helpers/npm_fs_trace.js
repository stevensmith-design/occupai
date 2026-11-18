// Test-only: loaded with `node --require` by a wrapper around the real npm. Logs every path npm
// opens, reads, writes or creates, so tests can prove which files npm touched.
const fs = require('fs');
const LOG = process.env.OCCUPAI_TRACE_LOG || (process.argv.find(a => a.startsWith('--occupai-trace=')) || '').slice(16);
let busy = false;
const log = (op, p) => {
  if (busy || !LOG || !(typeof p === 'string' || p instanceof URL || Buffer.isBuffer(p))) return;
  busy = true;
  try { fs.appendFileSync(LOG, op + '\t' + String(p) + '\n'); } catch (e) {} finally { busy = false; }
};
const wrap = (obj, names, op) => { for (const n of names) { const orig = obj[n]; if (typeof orig !== 'function') continue; obj[n] = function (p, ...rest) { log(op + ':' + n, p); return orig.call(this, p, ...rest); }; } };
wrap(fs, ['openSync', 'open', 'readFileSync', 'readFile', 'createReadStream', 'statSync', 'stat', 'lstatSync', 'lstat', 'accessSync', 'access', 'existsSync'], 'read');
wrap(fs, ['writeFileSync', 'writeFile', 'appendFile', 'createWriteStream', 'mkdirSync', 'mkdir', 'renameSync', 'rename', 'rmSync', 'rm', 'unlinkSync', 'unlink'], 'write');
wrap(fs.promises, ['open', 'readFile', 'stat', 'lstat', 'access', 'readdir'], 'read');
wrap(fs.promises, ['writeFile', 'appendFile', 'mkdir', 'rename', 'rm', 'unlink', 'mkdtemp'], 'write');
