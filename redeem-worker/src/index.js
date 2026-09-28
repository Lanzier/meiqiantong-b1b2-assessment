const encoder = new TextEncoder();

function corsHeaders(origin, env) {
  return {
    'Access-Control-Allow-Origin': origin === env.ALLOWED_ORIGIN ? origin : env.ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Cache-Control': 'no-store',
    'Vary': 'Origin'
  };
}

function json(data, status, origin, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...corsHeaders(origin, env) }
  });
}

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/g, '');
}

function decodeBase64url(value) {
  const normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  const binary = atob(normalized + '='.repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}

async function issueToken(secret, codeId) {
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url(encoder.encode(JSON.stringify({ sub: codeId, iat: now, exp: now + 86400, nonce: crypto.randomUUID() })));
  const signature = base64url(await hmac(secret, payload));
  return `${payload}.${signature}`;
}

async function verifyToken(secret, token) {
  if (!token || !token.includes('.')) return null;
  const [payload, suppliedSignature] = token.split('.');
  if (!payload || !suppliedSignature) return null;
  const expected = await hmac(secret, payload);
  const supplied = decodeBase64url(suppliedSignature);
  if (expected.length !== supplied.length) return null;
  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) mismatch |= expected[i] ^ supplied[i];
  if (mismatch) return null;
  try {
    const data = JSON.parse(new TextDecoder().decode(decodeBase64url(payload)));
    return data.exp > Math.floor(Date.now() / 1000) ? data : null;
  } catch {
    return null;
  }
}

async function sha256(value) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
  return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';
    if (request.method === 'OPTIONS') {
      if (origin !== env.ALLOWED_ORIGIN) return new Response(null, { status: 403 });
      return new Response(null, { status: 204, headers: corsHeaders(origin, env) });
    }
    if (origin !== env.ALLOWED_ORIGIN) return json({ ok: false, error: 'forbidden' }, 403, origin, env);
    const url = new URL(request.url);
    if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405, origin, env);

    if (url.pathname === '/verify') {
      const auth = request.headers.get('Authorization') || '';
      const session = await verifyToken(env.SESSION_SECRET, auth.startsWith('Bearer ') ? auth.slice(7) : '');
      return session ? json({ ok: true }, 200, origin, env) : json({ ok: false, error: 'invalid_session' }, 401, origin, env);
    }

    if (url.pathname !== '/redeem') return json({ ok: false, error: 'not_found' }, 404, origin, env);
    let body;
    try { body = await request.json(); } catch { return json({ ok: false, error: 'invalid_request' }, 400, origin, env); }
    const code = String(body?.code || '').trim().toUpperCase();
    if (!/^[A-Z0-9.-]{6,24}$/.test(code)) return json({ ok: false, error: 'invalid_code' }, 400, origin, env);
    const now = new Date().toISOString();
    const codeHash = await sha256(code);
    const row = await env.DB.prepare(`
      UPDATE redemption_codes
      SET used_count = CASE WHEN is_unlimited = 1 THEN used_count ELSE used_count + 1 END, last_used_at = ?
      WHERE code_hash = ? AND (is_unlimited = 1 OR used_count < max_uses) AND (is_unlimited = 1 OR expires_at > ?)
      RETURNING id, max_uses, used_count, expires_at, is_unlimited
    `).bind(now, codeHash, now).first();
    if (!row) return json({ ok: false, error: 'invalid_or_unavailable' }, 401, origin, env);
    const token = await issueToken(env.SESSION_SECRET, row.id);
    return json({ ok: true, token, unlimited: row.is_unlimited === 1, remaining: row.is_unlimited === 1 ? null : row.max_uses - row.used_count, expiresAt: row.is_unlimited === 1 ? null : row.expires_at }, 200, origin, env);
  }
};
