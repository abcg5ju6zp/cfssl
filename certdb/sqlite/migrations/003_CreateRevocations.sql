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
  serial_number            blob NOT NULL,
  authority_key_identifier blob NOT NULL,
  reason                   integer NOT NULL DEFAULT 0,
  revoked_at               timestamp NOT NULL,
  ocsp_body                blob,
  ocsp_expiry              timestamp,
  cert_committed           integer NOT NULL DEFAULT 0,
  ocsp_committed           integer NOT NULL DEFAULT 0,
  created_at               timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at               timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(serial_number, authority_key_identifier),
  FOREIGN KEY(serial_number, authority_key_identifier) REFERENCES certificates(serial_number, authority_key_identifier)
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE revocations;
