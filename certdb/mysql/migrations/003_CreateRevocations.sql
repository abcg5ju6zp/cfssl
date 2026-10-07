-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- revocations is the durable, resumable journal for a revocation
-- generation. A single row per (serial, AKI) fixes the authoritative
-- revocation reason/time on first write (repeat revocations are
-- idempotent), holds the signed OCSP candidate prepared before the
-- visible state switch, and records which steps have been committed so
-- that recovery after a failure or process exit only resumes
-- unconfirmed steps.
CREATE TABLE revocations (
  serial_number            varbinary(128) NOT NULL,
  authority_key_identifier varbinary(128) NOT NULL,
  reason                   int NOT NULL DEFAULT 0,
  revoked_at               timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  ocsp_body                varbinary(4096),
  ocsp_expiry              timestamp DEFAULT '0000-00-00 00:00:00',
  cert_committed           tinyint(1) NOT NULL DEFAULT 0,
  ocsp_committed           tinyint(1) NOT NULL DEFAULT 0,
  created_at               timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  updated_at               timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  PRIMARY KEY(serial_number, authority_key_identifier),
  CONSTRAINT fk_revocations_certificates FOREIGN KEY(serial_number, authority_key_identifier) REFERENCES certificates(serial_number, authority_key_identifier)
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE revocations;
