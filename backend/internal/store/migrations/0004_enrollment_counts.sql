-- Cover enrolment history and per-Mac key counts without reading credential payloads.
CREATE INDEX device_credentials_enrollment_counts_idx ON device_credentials (tenant_id, serial, created_at);
