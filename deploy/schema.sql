CREATE TABLE IF NOT EXISTS grants (
 subject text NOT NULL,
 tool text NOT NULL,
 PRIMARY KEY(subject,tool)
);
CREATE TABLE IF NOT EXISTS audit_events (
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 created_at timestamptz NOT NULL DEFAULT now(),
 request_id text NOT NULL,
 event jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_created_idx ON audit_events(created_at);
CREATE TABLE IF NOT EXISTS approvals (
 token_hash text PRIMARY KEY,
 subject text NOT NULL,
 digest text NOT NULL,
 expires_at timestamptz NOT NULL
);
-- Stable UUIDs match the imported demo realm users.
INSERT INTO grants(subject,tool) VALUES
 ('11111111-1111-4111-8111-111111111111','echo'),
 ('11111111-1111-4111-8111-111111111111','whoami'),
 ('11111111-1111-4111-8111-111111111111','restart_demo'),
 ('22222222-2222-4222-8222-222222222222','whoami')
ON CONFLICT DO NOTHING;
