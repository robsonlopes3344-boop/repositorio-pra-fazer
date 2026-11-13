import express from 'express';
import crypto from 'node:crypto';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

const scrypt = promisify(crypto.scrypt);
const admin = process.env.ADMIN_TOKEN || '';
const edgeUrl = process.env.EDGE_URL || '';
const edgeSecret = process.env.EDGE_SECRET || '';

if (admin.length < 32 || edgeSecret.length < 32 || !edgeUrl.startsWith('https://')) {
  throw Error('Configure ADMIN_TOKEN, EDGE_URL e EDGE_SECRET.');
}

const displayKey = crypto.createHash('sha256')
  .update('collins-license-display-v1\0')
  .update(edgeSecret)
  .digest();

async function backend(payload) {
  const response = await fetch(edgeUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-collins-backend': edgeSecret },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15000),
  });
  if (!response.ok) throw Error('backend indisponivel');
  return await response.json();
}

function sealLicenseKey(value) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', displayKey, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return ['v1', iv.toString('base64url'), cipher.getAuthTag().toString('base64url'), ciphertext.toString('base64url')].join('.');
}

function openLicenseKey(value) {
  try {
    const [version, iv, tag, ciphertext] = String(value || '').split('.');
    if (version !== 'v1' || !iv || !tag || !ciphertext) return null;
    const decipher = crypto.createDecipheriv('aes-256-gcm', displayKey, Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    const plain = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64url')), decipher.final()]).toString('utf8');
    return /^COLL-[A-F0-9]{24}$/.test(plain) ? plain : null;
  } catch {
    return null;
  }
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '4kb' }));
app.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Content-Security-Policy', "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
  next();
});
app.get('/admin', (_req, res) => res.sendFile(fileURLToPath(new URL('./admin.html', import.meta.url))));
app.get('/admin.js', (_req, res) => res.sendFile(fileURLToPath(new URL('./admin.js', import.meta.url))));
app.get('/admin.css', (_req, res) => res.sendFile(fileURLToPath(new URL('./admin.css', import.meta.url))));

const attempts = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [key, value] of attempts) if (now > value.end) attempts.delete(key);
}, 60000).unref();

function limit(req, res, next) {
  const key = req.ip || 'unknown';
  const now = Date.now();
  let value = attempts.get(key);
  if (!value || now > value.end) value = { n: 0, end: now + 60000 };
  attempts.set(key, value);
  if (++value.n > 30) return res.status(429).json({ error: 'limite' });
  next();
}

function authorized(req, res, next) {
  const supplied = Buffer.from(req.get('authorization') || '');
  const expected = Buffer.from('Bearer ' + admin);
  if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) {
    return res.status(401).json({ error: 'nao autorizado' });
  }
  next();
}

const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const validId = value => /^\d{1,15}$/.test(String(value || ''));
const validUser = value => typeof value === 'string' && /^[a-z0-9_]{4,24}$/.test(value);
const validDevice = value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const validPassword = value => typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 8 && Buffer.byteLength(value, 'utf8') <= 128;

async function makePassword(password) {
  const salt = crypto.randomBytes(16);
  const value = await scrypt(password, salt, 64);
  return 'scrypt$' + salt.toString('hex') + '$' + value.toString('hex');
}

async function checkPassword(password, encoded) {
  const parts = (encoded || '').split('$');
  if (parts.length !== 3 || parts[0] !== 'scrypt' || !/^[a-f0-9]{32}$/.test(parts[1]) || !/^[a-f0-9]{128}$/.test(parts[2])) return false;
  const value = await scrypt(password, Buffer.from(parts[1], 'hex'), 64);
  return crypto.timingSafeEqual(value, Buffer.from(parts[2], 'hex'));
}

function issueSession(username, deviceHash) {
  const payload = Buffer.from(JSON.stringify({ u: username, d: deviceHash, exp: Date.now() + 300000 })).toString('base64url');
  return payload + '.' + crypto.createHmac('sha256', admin).update(payload).digest('base64url');
}

function parseSession(token) {
  try {
    if (typeof token !== 'string' || token.length > 1024) return null;
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const supplied = Buffer.from(parts[1]);
    const expected = Buffer.from(crypto.createHmac('sha256', admin).update(parts[0]).digest('base64url'));
    if (supplied.length !== expected.length || !crypto.timingSafeEqual(supplied, expected)) return null;
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    return validUser(data.u) && validDevice(data.d) && Number.isFinite(data.exp) && data.exp > Date.now() ? data : null;
  } catch {
    return null;
  }
}

app.get('/health', async (_req, res) => {
  try { await backend({ op: 'health' }); res.json({ ok: true }); }
  catch { res.status(503).json({ ok: false }); }
});

app.post('/v1/verify', limit, (_req, res) => res.status(410).json({ valid: false, error: 'Use login e cadastro.' }));

app.post('/v1/register', limit, async (req, res) => {
  const username = String(req.body?.username || '').toLowerCase();
  const password = req.body?.password;
  const key = String(req.body?.key || '').trim().toUpperCase();
  const deviceHash = req.body?.device;
  if (!validUser(username) || !validPassword(password) || !/^COLL-[A-F0-9]{24}$/.test(key) || !validDevice(deviceHash)) {
    return res.status(400).json({ ok: false });
  }
  try {
    const passwordHash = await makePassword(password);
    const result = await backend({ op: 'register', username, passwordHash, keyHash: hash(key), deviceHash });
    return res.status(result.created ? 201 : 409).json({ ok: result.created === true });
  } catch {
    return res.status(503).json({ ok: false });
  }
});

app.post('/v1/login', limit, async (req, res) => {
  const username = String(req.body?.username || '').toLowerCase();
  const password = req.body?.password;
  const deviceHash = req.body?.device;
  if (!validUser(username) || !validPassword(password) || !validDevice(deviceHash)) return res.status(401).json({ ok: false });
  try {
    const result = await backend({ op: 'account', username });
    const account = result.account;
    if (!account || !await checkPassword(password, account.password_hash)) return res.status(401).json({ ok: false });
    const bind = await backend({ op: 'bindDevice', username, deviceHash });
    if (!bind.bound) return res.status(401).json({ ok: false, reason: 'hwid_mismatch' });
    if (typeof req.body?.shareSpecs === 'boolean') {
      const allow = ['os', 'cpu', 'gpu', 'ram', 'motherboard', 'storage', 'display', 'system'];
      const specs = {};
      if (req.body.shareSpecs) {
        if (!req.body.specs || typeof req.body.specs !== 'object' || Array.isArray(req.body.specs)) return res.status(400).json({ ok: false });
        for (const name of allow) {
          const value = req.body.specs[name];
          if (value !== undefined) {
            if (typeof value !== 'string' || value.length > 200) return res.status(400).json({ ok: false });
            specs[name] = value;
          }
        }
      }
      await backend({ op: 'specs', username, deviceHash, shared: req.body.shareSpecs, specs });
    }
    return res.json({ ok: true, session: issueSession(username, deviceHash) });
  } catch {
    return res.status(503).json({ ok: false });
  }
});

app.post('/v1/device-reset-requests', limit, async (req, res) => {
  const username = String(req.body?.username || '').toLowerCase();
  const password = req.body?.password;
  const newDeviceHash = req.body?.device;
  if (!validUser(username) || !validPassword(password) || !validDevice(newDeviceHash)) return res.status(400).json({ ok: false });
  try {
    const result = await backend({ op: 'account', username });
    const account = result.account;
    if (!account || !await checkPassword(password, account.password_hash)) return res.status(401).json({ ok: false });
    if (!account.device_hash || account.device_hash === newDeviceHash) return res.status(409).json({ ok: false, reason: 'reset_not_needed' });
    const request = await backend({ op: 'requestDeviceReset', username, newDeviceHash });
    return res.status(202).json({ ok: true, requestId: request.id, status: request.status });
  } catch {
    return res.status(503).json({ ok: false });
  }
});

app.post('/v1/session/verify', limit, async (req, res) => {
  const session = parseSession(req.body?.session);
  if (!session) return res.status(401).json({ valid: false });
  try {
    const result = await backend({ op: 'session', username: session.u, deviceHash: session.d });
    return res.status(result.valid ? 200 : 401).json({ valid: result.valid === true });
  } catch {
    return res.status(503).json({ valid: false });
  }
});

app.get('/v1/admin/keys', limit, authorized, async (_req, res) => {
  try {
    const rows = await backend({ op: 'list' });
    res.json(rows.map(row => {
      const key = openLicenseKey(row.key_ciphertext);
      const { key_ciphertext: _hidden, ...safe } = row;
      return { ...safe, key, keyRecoverable: !!key };
    }));
  } catch {
    res.status(503).json({ error: 'banco indisponivel' });
  }
});

app.post('/v1/admin/keys', limit, authorized, async (req, res) => {
  const days = req.body?.days ?? 30;
  const label = req.body?.label ?? '';
  if (!Number.isInteger(days) || days < 1 || days > 3650 || typeof label !== 'string' || label.length > 100) {
    return res.status(400).json({ error: 'dados invalidos' });
  }
  try {
    const key = 'COLL-' + crypto.randomBytes(12).toString('hex').toUpperCase();
    const result = await backend({ op: 'create', keyHash: hash(key), keyCiphertext: sealLicenseKey(key), label, days });
    res.status(201).json({ ...result, key });
  } catch {
    res.status(503).json({ error: 'banco indisponivel' });
  }
});

app.post('/v1/admin/keys/:id/rotate-key', limit, authorized, async (req, res) => {
  if (!validId(req.params.id)) return res.status(400).json({ error: 'id invalido' });
  try {
    const key = 'COLL-' + crypto.randomBytes(12).toString('hex').toUpperCase();
    const result = await backend({ op: 'rotateKey', id: req.params.id, keyHash: hash(key), keyCiphertext: sealLicenseKey(key) });
    return res.status(result.changed ? 200 : 404).json({ changed: result.changed === true, key: result.changed ? key : undefined });
  } catch {
    return res.status(503).json({ error: 'banco indisponivel' });
  }
});

app.post('/v1/admin/keys/:id/reset-device', limit, authorized, async (req, res) => {
  if (!validId(req.params.id)) return res.status(400).json({ error: 'id invalido' });
  try {
    const result = await backend({ op: 'resetDevice', id: req.params.id });
    return res.status(result.changed ? 200 : 404).json({ reset: result.changed === true });
  } catch {
    return res.status(503).json({ error: 'banco indisponivel' });
  }
});

app.post('/v1/admin/keys/:id/extend', limit, authorized, async (req, res) => {
  const days = req.body?.days;
  if (!validId(req.params.id) || !Number.isInteger(days) || days < 1 || days > 3650) return res.status(400).json({ error: 'dados invalidos' });
  try {
    const result = await backend({ op: 'extend', id: req.params.id, days });
    return res.status(result.changed ? 200 : 404).json(result);
  } catch {
    return res.status(503).json({ error: 'banco indisponivel' });
  }
});

app.post('/v1/admin/keys/:id/rename', limit, authorized, async (req, res) => {
  const label = req.body?.label;
  if (!validId(req.params.id) || typeof label !== 'string' || label.length > 100) return res.status(400).json({ error: 'dados invalidos' });
  try {
    const result = await backend({ op: 'rename', id: req.params.id, label });
    return res.status(result.changed ? 200 : 404).json(result);
  } catch {
    return res.status(503).json({ error: 'banco indisponivel' });
  }
});

for (const operation of ['revoke', 'unban']) {
  app.post(`/v1/admin/keys/:id/${operation}`, limit, authorized, async (req, res) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'id invalido' });
    try {
      const result = await backend({ op: operation, id: req.params.id });
      return res.status(result.changed ? 200 : 404).json({ changed: result.changed === true });
    } catch {
      return res.status(503).json({ error: 'banco indisponivel' });
    }
  });
}

app.get('/v1/admin/reset-requests', limit, authorized, async (_req, res) => {
  try { res.json(await backend({ op: 'listResetRequests' })); }
  catch { res.status(503).json({ error: 'banco indisponivel' }); }
});

for (const decision of ['approve', 'reject']) {
  app.post(`/v1/admin/reset-requests/:id/${decision}`, limit, authorized, async (req, res) => {
    if (!validId(req.params.id)) return res.status(400).json({ error: 'id invalido' });
    try {
      const result = await backend({ op: 'resolveResetRequest', id: req.params.id, decision });
      return res.status(result.changed ? 200 : 404).json(result);
    } catch {
      return res.status(503).json({ error: 'banco indisponivel' });
    }
  });
}

app.listen(Number(process.env.PORT || 3000), '0.0.0.0', () => console.log('Servidor iniciado'));


