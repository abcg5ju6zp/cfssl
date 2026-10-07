-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Records when the OCSP response body was produced, so that a delayed
-- refresh can never replace a newer response with an older candidate.
ALTER TABLE ocsp_responses ADD COLUMN generated_at timestamp NOT NULL DEFAULT '1970-01-01 00:00:00+00:00';

-- ocsp_responses_pending holds candidate responses that have been
-- generated and validated but not yet confirmed. A row with an empty body
-- marks a certificate that was selected for refresh but not signed yet.
-- Rows left here after a crash identify the certificates to continue on
-- the next run.
CREATE TABLE ocsp_responses_pending (
  serial_number            blob NOT NULL,
  authority_key_identifier blob NOT NULL,
  body                     blob NOT NULL,
  expiry                   timestamp,
  generated_at             timestamp NOT NULL DEFAULT '1970-01-01 00:00:00+00:00',
  PRIMARY KEY(serial_number, authority_key_identifier),
  FOREIGN KEY(serial_number, authority_key_identifier) REFERENCES certificates(serial_number, authority_key_identifier)
);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE ocsp_responses_pending;
ALTER TABLE ocsp_responses DROP COLUMN generated_at;
