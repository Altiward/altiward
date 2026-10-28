-- What an enrolling Mac said its MDM device ID is, and what Intune answered about it:
-- '' (not checked), 'not_sent', 'invalid_id', 'match', 'mismatch', 'unknown_id' or
-- 'unavailable'. A key made by rotation copies both from the key it replaced. Empty for a
-- key enrolled before this, which was never checked. The ID is kept for the record and
-- never shown or sent anywhere.
ALTER TABLE device_credentials
    ADD COLUMN mdm_device_id text NOT NULL DEFAULT '',
    ADD COLUMN mdm_check     text NOT NULL DEFAULT '';
