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

exports.main_handler = async (event) => {
  const headers = event.headers || {};
  const origin = headers.origin || headers.Origin || '';
  const method = String(event.httpMethod || event.requestContext?.httpMethod || '').toUpperCase();
  const rawPath = event.path || event.requestContext?.path || '/';
  const path = rawPath.endsWith('/verify') ? '/verify' : rawPath.endsWith('/redeem') ? '/redeem' : rawPath;

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

    if (path !== '/redeem') return response(404, { ok: false, error: 'not_found' });
    let rawBody = event.body || '';
    if (event.isBase64Encoded) rawBody = Buffer.from(rawBody, 'base64').toString('utf8');
    let body;
    try { body = JSON.parse(rawBody); } catch { return response(400, { ok: false, error: 'invalid_request' }); }
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
