ALTER TABLE attestation_bundles ADD COLUMN initiator TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE attestation_bundles ADD COLUMN transport_encoding TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE attestation_bundles ADD COLUMN wire_sha256 TEXT NOT NULL DEFAULT '';
ALTER TABLE attestation_bundles ADD COLUMN wire_bytes BLOB NOT NULL DEFAULT X'';
