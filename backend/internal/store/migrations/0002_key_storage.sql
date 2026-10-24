-- Where the Mac said its key is kept, as it enrolled: 'secure_enclave' or 'software'.
-- Empty for credentials from agents before 0.2.0, which don't say (they all hold file keys).
ALTER TABLE device_credentials ADD COLUMN key_storage text NOT NULL DEFAULT '';
