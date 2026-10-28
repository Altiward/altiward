-- History retention. Once expiry runs, the events table is no longer the full history, so
-- state (devices, sessions, the admin group) must never be rebuilt from it. Everything
-- expiry and the retired-Mac flag need is here.

-- Indexes for expiry, which walks the oldest rows of a tenant first. Only ended sessions
-- expire. They come first so that nothing below holds a lock on devices while they build.
CREATE INDEX events_received_idx ON events (tenant_id, received_at);
CREATE INDEX sessions_updated_ended_idx ON sessions (tenant_id, updated_at) WHERE ended_at IS NOT NULL;
-- Deleting an event checks the outbox's foreign key to it, and expiry filters out events
-- still waiting to be sent with NOT EXISTS. The unique index on the outbox leads with the
-- sink, which neither of those has.
CREATE INDEX export_outbox_event_idx ON export_outbox (tenant_id, event_id);

-- A retired Mac: NULL means not retired. admin_group is what the Mac last reported as its
-- admin group; NULL means nothing reported yet.
ALTER TABLE devices
    ADD COLUMN retired_at  timestamptz,
    ADD COLUMN admin_group jsonb;

-- Existing Macs that an admin has retired count as retired from then on. Take each serial's
-- newest revoked key (the later device_id if two share a time), and only if every key for
-- the serial is revoked and none is pending. The Mac is retired if that key was once active
-- (activated_at is set: a rejected pending key never was, so rejecting a re-enrolment after
-- a contest doesn't retire the Mac) and an admin's revoke_enrollment entry targets it,
-- written no later than the revocation (a revoke that changed nothing keeps the old
-- revoked_at and writes a later entry, so it doesn't count). An old contest, where the
-- server revoked the key itself, leaves no entry. retired_at is that key's revoked_at.
UPDATE devices d
   SET retired_at = k.revoked_at
  FROM (SELECT DISTINCT ON (tenant_id, serial) tenant_id, serial, device_id, revoked_at, activated_at
          FROM device_credentials
         WHERE status = 'revoked' AND revoked_at IS NOT NULL
         ORDER BY tenant_id, serial, revoked_at DESC, device_id DESC) k
 WHERE d.tenant_id = k.tenant_id
   AND d.serial = k.serial
   AND k.activated_at IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM device_credentials c
                    WHERE c.tenant_id = d.tenant_id AND c.serial = d.serial AND c.status <> 'revoked')
   AND EXISTS (SELECT 1 FROM audit_log a
                WHERE a.tenant_id = k.tenant_id
                  AND a.action = 'revoke_enrollment'
                  AND a.target = k.device_id::text
                  AND a.at <= k.revoked_at);

-- The secret that keys the IDs of events the server raises itself (32 random bytes from
-- the database, stored once), when the admin group's history started, and when the
-- backfill of it finished (NULL until it has; expiry doesn't start before then). The
-- defaults fill the one existing row.
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

-- Floors that don't trust the application: a DELETE of a row is refused until the row is
-- more than 90 days old by the database's clock, by the column named in each function.
-- Expiry keeps to its own, longer limits; this stops a bug or a stray statement from
-- deleting recent history. Like the audit log's trigger, it guards DELETE statements:
-- TRUNCATE, or dropping the trigger, needs the table's owner. Loosening it takes a
-- deliberate schema change.
CREATE FUNCTION events_retention_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.received_at < now() - interval '90 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'events rows younger than 90 days cannot be deleted';
END $$;
CREATE TRIGGER events_retention_floor BEFORE DELETE ON events
    FOR EACH ROW EXECUTE FUNCTION events_retention_floor();

CREATE FUNCTION sessions_retention_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.updated_at < now() - interval '90 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'sessions rows younger than 90 days cannot be deleted';
END $$;
CREATE TRIGGER sessions_retention_floor BEFORE DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION sessions_retention_floor();

CREATE FUNCTION devices_retention_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.last_seen_at < now() - interval '90 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'devices rows younger than 90 days cannot be deleted';
END $$;
CREATE TRIGGER devices_retention_floor BEFORE DELETE ON devices
    FOR EACH ROW EXECUTE FUNCTION devices_retention_floor();

CREATE FUNCTION agent_commands_retention_floor() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.created_at < now() - interval '90 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'agent_commands rows younger than 90 days cannot be deleted';
END $$;
CREATE TRIGGER agent_commands_retention_floor BEFORE DELETE ON agent_commands
    FOR EACH ROW EXECUTE FUNCTION agent_commands_retention_floor();
