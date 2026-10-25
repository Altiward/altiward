-- Enable approval once for existing installations. Earlier false values may be the
-- previous implicit default. Administrators can explicitly opt out after this upgrade.
-- Leave credentials and all other tenant settings unchanged.
UPDATE tenant_settings
SET settings = jsonb_set(COALESCE(NULLIF(settings, 'null'::jsonb), '{}'::jsonb),
                         '{reenrollment_requires_approval}', 'true'::jsonb, true),
    updated_at = now();
