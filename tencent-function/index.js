'use strict';

const https = require('https');
const crypto = require('crypto');

const ALLOWED_ORIGIN = 'https://lanzier.github.io';
const CLOUDFLARE_ACCOUNT_ID = '1b2ae3125ea96904d221ad44fba429b6';
const D1_DATABASE_ID = '6300a9fd-fe5e-4665-9adc-6ca2b173d60e';

function response(statusCode, body) {
  return {
    isBase64Encoded: false,
    statusCode,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Max-Age': '86400',
      'Cache-Control': 'no-store',
      'Vary': 'Origin'
    },
    body: typeof body === 'string' ? body : JSON.stringify(body)
  };
}

function base64url(value) {
  return Buffer.from(value).toString('base64').replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
}

function decodeBase64url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return Buffer.from(normalized + '='.repeat((4 - normalized.length % 4) % 4), 'base64');
}

function sign(secret, value) {
  return crypto.createHmac('sha256', secret).update(value).digest();
}

function issueToken(secret, codeId) {
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(JSON.stringify({ sub: codeId, iat: now, exp: now + 86400, nonce: crypto.randomUUID() }));
  return `${payload}.${base64url(sign(secret, payload))}`;
}

function verifyToken(secret, token) {
  if (!token || !token.includes('.')) return null;
  const [payload, suppliedValue] = token.split('.');
  if (!payload || !suppliedValue) return null;
  const expected = sign(secret, payload);
  const supplied = decodeBase64url(suppliedValue);
  if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return null;
  try {
    const data = JSON.parse(decodeBase64url(payload).toString('utf8'));
    return data.exp > Math.floor(Date.now() / 1000) ? data : null;
  } catch {
    return null;
  }
}

function normalizeOrderNumber(value) {
  return String(value || '').trim().toUpperCase().replace(/\s+/g, '');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function encryptCode(secret, code) {
  const key = crypto.createHash('sha256').update(secret).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(code, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString('base64');
}

function decryptCode(secret, value) {
  const data = Buffer.from(value, 'base64');
  const key = crypto.createHash('sha256').update(secret).digest();
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAuthTag(data.subarray(12, 28));
  return Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]).toString('utf8');
}

function cloudflareQuery(sql, params = []) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({ sql, params });
    const request = https.request({
      hostname: 'api.cloudflare.com',
      port: 443,
      path: `/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}/query`,
      method: 'POST',
      timeout: 10000,
      headers: {
        'Authorization': `Bearer ${process.env.CF_API_TOKEN || ''}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }, upstream => {
      let data = '';
      upstream.setEncoding('utf8');
      upstream.on('data', chunk => { data += chunk; });
      upstream.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (upstream.statusCode < 200 || upstream.statusCode >= 300 || !parsed.success) return reject(new Error(`d1_api_${upstream.statusCode || 500}`));
          const result = parsed.result?.[0];
          if (!result?.success) return reject(new Error('d1_query_failed'));
          resolve(result.results || []);
        } catch (error) {
          reject(error);
        }
      });
    });
    request.on('timeout', () => request.destroy(new Error('d1_timeout')));
    request.on('error', reject);
    request.end(body);
  });
}

async function redeem(code) {
  const now = new Date().toISOString();
  const firstUseExpiry = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString();
  const codeHash = crypto.createHash('sha256').update(code).digest('hex');
  const rows = await cloudflareQuery(`
    UPDATE redemption_codes
    SET used_count = CASE WHEN is_unlimited = 1 THEN used_count ELSE used_count + 1 END,
        first_used_at = CASE WHEN is_unlimited = 1 THEN first_used_at ELSE COALESCE(first_used_at, ?) END,
        expires_at = CASE WHEN is_unlimited = 1 THEN expires_at WHEN first_used_at IS NULL THEN ? ELSE expires_at END,
        last_used_at = ?
    WHERE code_hash = ?
      AND (is_unlimited = 1 OR used_count < max_uses)
      AND (is_unlimited = 1 OR first_used_at IS NULL OR expires_at > ?)
    RETURNING id, max_uses, used_count, first_used_at, expires_at, is_unlimited
  `, [now, firstUseExpiry, now, codeHash, now]);
  return rows[0] || null;
}

async function ensurePickupTable() {
  await cloudflareQuery(`
    CREATE TABLE IF NOT EXISTS pickup_orders (
      order_hash TEXT PRIMARY KEY,
      code_hash TEXT NOT NULL,
      code_cipher TEXT NOT NULL,
      created_at TEXT NOT NULL,
      claimed_at TEXT
    )
  `);
  await cloudflareQuery('CREATE UNIQUE INDEX IF NOT EXISTS pickup_orders_code_hash_unique ON pickup_orders(code_hash)');
}

async function isAdminCode(code) {
  const normalizedCode = String(code || '').trim().toUpperCase();
  const rows = await cloudflareQuery(
    'SELECT id FROM redemption_codes WHERE code_hash = ? AND is_unlimited = 1 LIMIT 1',
    [sha256(normalizedCode)]
  );
  return Boolean(rows[0]);
}

async function importPickupOrders(secret, orders) {
  await ensurePickupTable();
  const now = new Date().toISOString();
  let imported = 0;
  let skipped = 0;
  for (const item of orders) {
    const orderNumber = normalizeOrderNumber(item?.orderNumber);
    const code = String(item?.code || '').trim().toUpperCase();
    if (!/^[A-Z0-9-]{10,40}$/.test(orderNumber) || !/^[A-Z0-9.-]{6,24}$/.test(code)) { skipped += 1; continue; }
    const codeHash = sha256(code);
    const exists = await cloudflareQuery('SELECT id FROM redemption_codes WHERE code_hash = ? LIMIT 1', [codeHash]);
    if (!exists[0]) { skipped += 1; continue; }
    const assigned = await cloudflareQuery(
      'SELECT order_hash, code_hash FROM pickup_orders WHERE order_hash = ? OR code_hash = ? LIMIT 1',
      [sha256(orderNumber), codeHash]
    );
    if (assigned[0]) { skipped += 1; continue; }
    await cloudflareQuery(`
      INSERT INTO pickup_orders (order_hash, code_hash, code_cipher, created_at, claimed_at)
      VALUES (?, ?, ?, ?, NULL)
    `, [sha256(orderNumber), codeHash, encryptCode(secret, code), now]);
    imported += 1;
  }
  return { imported, skipped };
}

function generateRedemptionCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(12);
  let value = '';
  for (let i = 0; i < bytes.length; i += 1) value += alphabet[bytes[i] % alphabet.length];
  return `EV-${value.slice(0, 4)}-${value.slice(4, 8)}-${value.slice(8, 12)}`;
}

async function autoAssignPickupOrders(secret, orders) {
  await ensurePickupTable();
  const now = new Date().toISOString();
  let imported = 0;
  let skipped = 0;
  const assigned = [];
  for (const item of orders) {
    const orderNumber = normalizeOrderNumber(item?.orderNumber);
    if (!/^[A-Z0-9-]{10,40}$/.test(orderNumber)) { skipped += 1; continue; }
    const orderHash = sha256(orderNumber);
    const existing = await cloudflareQuery('SELECT code_cipher FROM pickup_orders WHERE order_hash = ? LIMIT 1', [orderHash]);
    if (existing[0]) {
      assigned.push({ orderNumber, code: decryptCode(secret, existing[0].code_cipher), created: false });
      continue;
    }
    let code = '';
    let codeHash = '';
    for (let attempt = 0; attempt < 5; attempt += 1) {
      code = generateRedemptionCode();
      codeHash = sha256(code);
      const duplicate = await cloudflareQuery('SELECT id FROM redemption_codes WHERE code_hash = ? LIMIT 1', [codeHash]);
      if (!duplicate[0]) break;
      code = '';
    }
    if (!code) { skipped += 1; continue; }
    const codeId = `EV-AUTO-${Date.now()}-${crypto.randomBytes(3).toString('hex').toUpperCase()}`;
    await cloudflareQuery(`
      INSERT INTO redemption_codes
        (id, code_hash, code_hint, max_uses, used_count, is_unlimited, created_at, first_used_at, expires_at, last_used_at)
      VALUES (?, ?, ?, 5, 0, 0, ?, NULL, '9999-12-31T23:59:59.999Z', NULL)
    `, [codeId, codeHash, code.slice(-4), now]);
    await cloudflareQuery(`
      INSERT INTO pickup_orders (order_hash, code_hash, code_cipher, created_at, claimed_at)
      VALUES (?, ?, ?, ?, NULL)
    `, [orderHash, codeHash, encryptCode(secret, code), now]);
    imported += 1;
    assigned.push({ orderNumber, code, created: true });
  }
  return { imported, skipped, assigned };
}

async function pickupOrder(secret, orderNumber) {
  await ensurePickupTable();
  const orderHash = sha256(orderNumber);
  const rows = await cloudflareQuery('SELECT code_cipher, claimed_at FROM pickup_orders WHERE order_hash = ? LIMIT 1', [orderHash]);
  if (!rows[0]) return null;
  const claimedAt = rows[0].claimed_at || new Date().toISOString();
  if (!rows[0].claimed_at) await cloudflareQuery('UPDATE pickup_orders SET claimed_at = ? WHERE order_hash = ?', [claimedAt, orderHash]);
  return { code: decryptCode(secret, rows[0].code_cipher), claimedAt };
}

exports.main_handler = async (event) => {
  const headers = event.headers || {};
  const origin = headers.origin || headers.Origin || '';
  const method = String(event.httpMethod || event.requestContext?.httpMethod || '').toUpperCase();
  const rawPath = event.path || event.requestContext?.path || '/';
  const path = rawPath.endsWith('/pickup/import') ? '/pickup/import' : rawPath.endsWith('/pickup') ? '/pickup' : rawPath.endsWith('/verify') ? '/verify' : rawPath.endsWith('/redeem') ? '/redeem' : rawPath;

  if (origin !== ALLOWED_ORIGIN) return response(403, { ok: false, error: 'forbidden' });
  if (method === 'OPTIONS') return response(204, '');
  if (method !== 'POST') return response(405, { ok: false, error: 'method_not_allowed' });
  if (!process.env.CF_API_TOKEN || !process.env.SESSION_SECRET) return response(500, { ok: false, error: 'service_not_configured' });

  try {
    if (path === '/verify') {
      const auth = headers.authorization || headers.Authorization || '';
      const session = verifyToken(process.env.SESSION_SECRET, auth.startsWith('Bearer ') ? auth.slice(7) : '');
      if (!session) return response(401, { ok: false, error: 'invalid_session' });
      const rows = await cloudflareQuery('SELECT is_unlimited FROM redemption_codes WHERE id = ?', [session.sub]);
      return rows[0] ? response(200, { ok: true, unlimited: rows[0].is_unlimited === 1 }) : response(401, { ok: false, error: 'invalid_session' });
    }

    let rawBody = event.body || '';
    if (event.isBase64Encoded) rawBody = Buffer.from(rawBody, 'base64').toString('utf8');
    let body;
    try { body = JSON.parse(rawBody); } catch { return response(400, { ok: false, error: 'invalid_request' }); }

    if (path === '/pickup') {
      const orderNumber = normalizeOrderNumber(body?.orderNumber);
      if (!/^[A-Z0-9-]{10,40}$/.test(orderNumber)) return response(400, { ok: false, error: 'invalid_order_number' });
      const result = await pickupOrder(process.env.SESSION_SECRET, orderNumber);
      return result ? response(200, { ok: true, code: result.code, claimedAt: result.claimedAt }) : response(404, { ok: false, error: 'order_not_found' });
    }

    if (path === '/pickup/import') {
      const adminCode = String(body?.adminCode || '').trim();
      if (!await isAdminCode(adminCode)) return response(403, { ok: false, error: 'forbidden' });
      const orders = Array.isArray(body?.orders) ? body.orders.slice(0, 100) : [];
      const automatic = orders.every(item => !String(item?.code || '').trim());
      const result = automatic
        ? await autoAssignPickupOrders(process.env.SESSION_SECRET, orders)
        : await importPickupOrders(process.env.SESSION_SECRET, orders);
      return response(200, { ok: true, ...result });
    }

    if (path !== '/redeem') return response(404, { ok: false, error: 'not_found' });
    const code = String(body?.code || '').trim().toUpperCase();
    if (!/^[A-Z0-9.-]{6,24}$/.test(code)) return response(400, { ok: false, error: 'invalid_code' });
    const row = await redeem(code);
    if (!row) return response(401, { ok: false, error: 'invalid_or_unavailable' });
    return response(200, {
      ok: true,
      token: issueToken(process.env.SESSION_SECRET, row.id),
      unlimited: row.is_unlimited === 1,
      remaining: row.is_unlimited === 1 ? null : row.max_uses - row.used_count,
      expiresAt: row.is_unlimited === 1 ? null : row.expires_at
    });
  } catch (error) {
    console.error('Verification request failed:', error.message);
    return response(502, { ok: false, error: 'database_unavailable' });
  }
};
