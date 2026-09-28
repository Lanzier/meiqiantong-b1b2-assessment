ALTER TABLE redemption_codes ADD COLUMN first_used_at TEXT;

UPDATE redemption_codes
SET first_used_at = CASE
      WHEN is_unlimited = 0 AND used_count > 0 THEN last_used_at
      ELSE NULL
    END,
    expires_at = CASE
      WHEN is_unlimited = 1 THEN expires_at
      WHEN used_count > 0 THEN strftime('%Y-%m-%dT%H:%M:%fZ', last_used_at, '+30 days')
      ELSE '9999-12-31T23:59:59.999Z'
    END;
