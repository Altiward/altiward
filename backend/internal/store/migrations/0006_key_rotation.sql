-- Key rotation. A rotated key stays 'revoked'; these columns link it to the key that
-- replaced it. rotated_from is the key a rotation replaced, rotation_signed_at when the Mac
-- signed that rotation, and stale_use_reported_at when a use of this key after its rotation
-- was last reported. NULL means "not made by rotation" and "never reported", so existing
-- rows read as before. The unique index gives a key at most one successor.
ALTER TABLE device_credentials
    ADD COLUMN rotated_from uuid REFERENCES device_credentials (device_id),
    ADD COLUMN rotation_signed_at timestamptz,
    ADD COLUMN stale_use_reported_at timestamptz,
    ADD CONSTRAINT device_credentials_rotated_from_check CHECK (rotated_from <> device_id);
CREATE UNIQUE INDEX device_credentials_rotated_from_idx ON device_credentials (rotated_from) WHERE rotated_from IS NOT NULL;
