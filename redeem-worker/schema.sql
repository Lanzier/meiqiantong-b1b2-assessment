CREATE TABLE IF NOT EXISTS redemption_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  code_hint TEXT NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 5 CHECK (max_uses > 0),
  used_count INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0),
  is_unlimited INTEGER NOT NULL DEFAULT 0 CHECK (is_unlimited IN (0, 1)),
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_redemption_codes_hash
  ON redemption_codes(code_hash);

CREATE INDEX IF NOT EXISTS idx_redemption_codes_expiry
  ON redemption_codes(expires_at);
