-- A copy of the Macs an MDM manages (Intune, as source 'intune'), replaced whole at each
-- sync and deleted when the connection is turned off. device_id is the MDM's own ID,
-- lower-cased. '-infinity' in last_check_in means the Mac has never checked in, and reads
-- as Go's zero time.
CREATE TABLE mdm_devices (
    tenant_id       text        NOT NULL,
    source          text        NOT NULL,
    device_id       text        NOT NULL,
    serial          text        NOT NULL DEFAULT '',
    entra_device_id text        NOT NULL DEFAULT '',
    primary_upn     text        NOT NULL DEFAULT '',
    name            text        NOT NULL DEFAULT '',
    last_check_in   timestamptz NOT NULL DEFAULT '-infinity',
    PRIMARY KEY (tenant_id, source, device_id)
);
CREATE INDEX mdm_devices_serial_idx ON mdm_devices (tenant_id, source, upper(btrim(serial)));

-- Each copy's sync. claimed_at is when a replica last claimed the sync, so only one runs
-- it at a time; '-infinity' means never. NULL times mean never.
CREATE TABLE mdm_sync (
    tenant_id       text        NOT NULL,
    source          text        NOT NULL,
    claimed_at      timestamptz NOT NULL DEFAULT '-infinity',
    last_success_at timestamptz,
    last_error_at   timestamptz,
    last_error      text        NOT NULL DEFAULT '',
    devices         int         NOT NULL DEFAULT 0,
    silence_held_at timestamptz,
    silence_held    int         NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, source)
);
