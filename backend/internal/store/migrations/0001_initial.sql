-- The schema of the first release. Later changes go in new migrations; never edit this one.

-- Raw events, exactly as received. The source of truth; sessions and devices are derived.
CREATE TABLE events (
    tenant_id     text        NOT NULL,
    event_id      uuid        NOT NULL,
    type          text        NOT NULL,
    session_id    uuid,
    device_serial text        NOT NULL,
    occurred_at   timestamptz NOT NULL,
    received_at   timestamptz NOT NULL,
    body          jsonb       NOT NULL,
    PRIMARY KEY (tenant_id, event_id)
);
CREATE INDEX events_session_idx ON events (tenant_id, session_id, occurred_at) WHERE session_id IS NOT NULL;
CREATE INDEX events_device_idx ON events (tenant_id, device_serial, occurred_at);

-- Elevation sessions. `state` is the full session.Session; the other columns exist for
-- filtering.
CREATE TABLE sessions (
    tenant_id     text        NOT NULL,
    session_id    uuid        NOT NULL,
    device_serial text        NOT NULL,
    local_user    text        NOT NULL,
    started_at    timestamptz,
    ended_at      timestamptz,
    state         jsonb       NOT NULL,
    updated_at    timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, session_id)
);
CREATE INDEX sessions_started_idx ON sessions (tenant_id, started_at DESC NULLS LAST);
CREATE INDEX sessions_user_idx ON sessions (tenant_id, local_user, started_at DESC);
CREATE INDEX sessions_device_idx ON sessions (tenant_id, device_serial, started_at DESC);
CREATE INDEX sessions_open_idx ON sessions (tenant_id) WHERE ended_at IS NULL;

-- The fleet inventory and who is admin now. `state` is the full session.Device.
CREATE TABLE devices (
    tenant_id    text        NOT NULL,
    serial       text        NOT NULL,
    state        jsonb       NOT NULL,
    last_seen_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, serial)
);
-- The silence monitor looks for devices that have stopped checking in, across tenants.
CREATE INDEX devices_last_seen_idx ON devices (last_seen_at);
CREATE INDEX devices_silent_idx ON devices (tenant_id, serial) WHERE state->'silence'->>'state' = 'silent';

-- Per-device agent credentials.
CREATE TABLE device_credentials (
    device_id     uuid        PRIMARY KEY,
    tenant_id     text        NOT NULL,
    serial        text        NOT NULL,
    hardware_uuid text        NOT NULL,
    public_key    bytea       NOT NULL,
    key_digest    bytea       NOT NULL UNIQUE,
    status        text        NOT NULL CHECK (status IN ('active', 'pending', 'revoked')),
    created_at    timestamptz NOT NULL,
    activated_at  timestamptz,
    revoked_at    timestamptz
);
-- At most one active credential per Mac.
CREATE UNIQUE INDEX device_credentials_active_idx ON device_credentials (tenant_id, serial) WHERE status = 'active';
CREATE INDEX device_credentials_tenant_idx ON device_credentials (tenant_id, created_at DESC);

CREATE TABLE tenant_settings (
    tenant_id  text        PRIMARY KEY,
    settings   jsonb       NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Remote commands for agents.
CREATE TABLE agent_commands (
    command_id   uuid        PRIMARY KEY,
    tenant_id    text        NOT NULL,
    serial       text        NOT NULL,
    type         text        NOT NULL,
    user_name    text,
    session_id   uuid,
    issued_by    text        NOT NULL,
    created_at   timestamptz NOT NULL,
    expires_at   timestamptz NOT NULL,
    delivered_at timestamptz,
    result       jsonb,
    result_at    timestamptz
);
CREATE INDEX agent_commands_pending_idx ON agent_commands (tenant_id, serial, created_at) WHERE result IS NULL;
CREATE INDEX agent_commands_tenant_idx ON agent_commands (tenant_id, created_at DESC);

-- Console actions, written in the same transaction as the change each records. Entries
-- recorded in the same instant list in the order they were recorded (seq), and a page
-- boundary between them skips neither.
CREATE TABLE audit_log (
    tenant_id text        NOT NULL,
    id        uuid        NOT NULL,
    at        timestamptz NOT NULL,
    actor     text        NOT NULL,
    action    text        NOT NULL,
    target    text        NOT NULL,
    detail    jsonb       NOT NULL,
    seq       bigint      GENERATED ALWAYS AS IDENTITY,
    PRIMARY KEY (tenant_id, id)
);
CREATE INDEX audit_log_at_idx ON audit_log (tenant_id, at DESC, seq DESC);

-- Append-only: updates fail, and so does deleting an entry until it is more than 365 days
-- old by the database's clock. A deployment may set ALTIWARD_AUDIT_RETENTION_DAYS, at
-- least 365, to remove old entries. Loosening this takes a deliberate schema change.
CREATE FUNCTION audit_log_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND OLD.at < now() - interval '365 days' THEN
        RETURN OLD;
    END IF;
    RAISE EXCEPTION 'audit_log is append-only';
END $$;
CREATE TRIGGER audit_log_append_only BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- What each SIEM sink is owed: an event or an audit entry, never both. Written in the
-- transaction that stores the item; drained by export workers, so events and console
-- actions share each sink's queue, retries and backlog.
CREATE TABLE export_outbox (
    id              bigserial   PRIMARY KEY,
    tenant_id       text        NOT NULL,
    sink            text        NOT NULL,
    event_id        uuid,
    attempts        integer     NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL,
    leased_until    timestamptz,
    last_error      text,
    created_at      timestamptz NOT NULL DEFAULT now(),
    audit_id        uuid,
    UNIQUE (tenant_id, sink, event_id),
    FOREIGN KEY (tenant_id, event_id) REFERENCES events (tenant_id, event_id),
    CONSTRAINT export_outbox_audit_fkey
        FOREIGN KEY (tenant_id, audit_id) REFERENCES audit_log (tenant_id, id),
    CONSTRAINT export_outbox_one_item CHECK ((event_id IS NULL) <> (audit_id IS NULL))
);
CREATE INDEX export_outbox_due_idx ON export_outbox (sink, next_attempt_at);
CREATE UNIQUE INDEX export_outbox_audit_key ON export_outbox (tenant_id, sink, audit_id)
    WHERE audit_id IS NOT NULL;

-- When each sink last delivered something for a tenant, for the console's SIEM rows.
-- Delivered rows leave export_outbox, so the time is kept here, written in the same
-- statement that deletes them.
CREATE TABLE export_deliveries (
    tenant_id         text        NOT NULL,
    sink              text        NOT NULL,
    last_delivered_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, sink)
);

-- Console sign-in sessions. The cookie holds a random token; only its SHA-256 is
-- stored. expires_at is ends_at, or sooner once the session goes unused.
CREATE TABLE console_sessions (
    token_hash bytea       PRIMARY KEY,
    tenant_id  text        NOT NULL,
    subject    text        NOT NULL,
    actor      text        NOT NULL,
    name       text        NOT NULL,
    role       text        NOT NULL,
    csrf_token text        NOT NULL,
    created_at timestamptz NOT NULL,
    ends_at    timestamptz NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX console_sessions_expires_idx ON console_sessions (expires_at);

-- One row describing this server: when its database was set up.
CREATE TABLE installation (
    id         boolean     PRIMARY KEY DEFAULT true CHECK (id),
    created_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO installation DEFAULT VALUES;
