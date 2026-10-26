-- The audit name of the enrolment token that enrolled each key: "token:" and 8 hex digits
-- of its SHA-256, never the token. Empty for keys enrolled before server 0.9.0.
ALTER TABLE device_credentials ADD COLUMN token text NOT NULL DEFAULT '';
