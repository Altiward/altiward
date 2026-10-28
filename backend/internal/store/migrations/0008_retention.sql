-- History retention. Once expiry runs, the events table is no longer the full history, so
-- state (devices, sessions, the admin group) must never be rebuilt from it. Everything
-- expiry and the retired-Mac flag need is here.

-- A retired Mac: NULL means not retired. admin_group is what the Mac last reported as its
-- admin group; NULL means nothing reported yet.
ALTER TABLE devices
    ADD COLUMN retired_at  timestamptz,
    ADD COLUMN admin_group jsonb;

-- Existing Macs whose keys an admin revoked count as retired from then on: every key for
-- the serial is revoked, none is pending, and the newest revocation matches a
-- revoke_enrollment entry in the audit log that targets that key. An old contest, where
-- the server revoked the key itself, leaves no such entry and so isn't mistaken for an
-- admin. retired_at is that key's revoked_at.
UPDATE devices d
   SET retired_at = k.revoked_at
  FROM (SELECT DISTINCT ON (tenant_id, serial) tenant_id, serial, device_id, revoked_at
          FROM device_credentials
         WHERE status = 'revoked' AND revoked_at IS NOT NULL
         ORDER BY tenant_id, serial, revoked_at DESC) k
 WHERE d.tenant_id = k.tenant_id
   AND d.serial = k.serial
   AND NOT EXISTS (SELECT 1 FROM device_credentials c
                    WHERE c.tenant_id = d.tenant_id AND c.serial = d.serial AND c.status <> 'revoked')
   AND EXISTS (SELECT 1 FROM audit_log a
                WHERE a.tenant_id = k.tenant_id
                  AND a.action = 'revoke_enrollment'
                  AND a.target = k.device_id::text);

-- The secret that keys the IDs of events the server raises itself X-- from the database, stored once), when the admin group's history started, and when the
-- backfill of it finished (NULL until it has; expiry doesn't start before then). The
-- default fills the one existing row.
ALTER TABLE installation
    ADD COLUMN raised_id_secret          bytea       NOT NULL DEFAULT (uuid_send(gen_random_uuid()) || uuid_send(gen_random_uuid())),
    ADD COLUMN admin_group_started_at    timestamptz NOT NULL DEFAULT now(),
    ADD COLUMN admin_group_backfilled_at timestamptz;

-- From when each SIEM sink has been sent everything. A sink added later is replayed from
-- the events still held, so history expiry must not outrun it.
CREATE TABLE export_sinks (
    sink         text        PRIMARY KEY,
    covered_from timestamptz NOT NULL
);

-- Indexes for expiry, which walks the oldest rows of a tenant first. Only ended sessions
-- expire.
CREATE INDEX events_received_idx ON events (tenant_id, received_at);
CREATE INDEX sessions_updated_ended_idx ON sessions (tenant_id, updated_at) WHERE ended_at IS NOT NULL;

-- Floors that don't trust the application: a row is refused deletion until it is more than
-- 90 days old by the database's clock, whichever column below says how old it is. Expiry
-- keeps to its own, longer limits; this stops a bug or a stray statement from deleting
-- recent history. Loosening it takes a deliberate schema change.
CREATE FUNCTION retention_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(OLD) ->> TG_ARGV[0])::timestamptz < now() - interval '90 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION '% rows younger than 90 days cannot be deleted', TG_TABLE_NAME;
END $$;
CREATE TRIGGER events_retention_floor BEFORE DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION retention_floor('received_at');
CREATE TRIGGER sessions_retention_floor BEFORE DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION retention_floor('updated_at');
CREATE TRIGGER devices_retention_floor BEFORE DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION retention_floor('last_seen_at');
CREATE TRIGGER agent_commands_retention_floor BEFORE DELETE ON agent_commands
    FOR EACH ROW EXECUTE FUNCTION retention_floor('created_at');
