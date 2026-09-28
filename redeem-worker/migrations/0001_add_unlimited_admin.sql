ALTER TABLE redemption_codes ADD COLUMN is_unlimited INTEGER NOT NULL DEFAULT 0 CHECK (is_unlimited IN (0, 1));

INSERT OR IGNORE INTO redemption_codes (id, code_hash, code_hint, max_uses, used_count, is_unlimited, created_at, expires_at) VALUES
('ADMIN-001','4489eb849bff380a2e32818ada17790b392e7b2c2e2cebdb9329a5db30964fb5','3456',1,0,1,'2026-09-28T00:00:00.000Z','9999-12-31T23:59:59.999Z');
