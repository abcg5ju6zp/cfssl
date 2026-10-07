package sql

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	cferr "github.com/cloudflare/cfssl/errors"
	"github.com/kisielk/sqlstruct"

	stdocsp "golang.org/x/crypto/ocsp"
)

const (
	insertRevocationSQL = `
INSERT INTO revocations (serial_number, authority_key_identifier, reason, revoked_at, created_at, updated_at)
VALUES (:serial_number, :authority_key_identifier, :reason, :revoked_at, :created_at, :updated_at);`

	selectRevocationSQL = `
SELECT %s FROM revocations
	WHERE (serial_number = ? AND authority_key_identifier = ?);`

	selectPendingRevocationsSQL = `
SELECT %s FROM revocations
	WHERE cert_committed = 0
	   OR (ocsp_body IS NOT NULL AND ocsp_body <> '' AND ocsp_committed = 0);`

	setRevocationOCSPSQL = `
UPDATE revocations
	SET ocsp_body=:ocsp_body, ocsp_expiry=:ocsp_expiry, updated_at=:updated_at
	WHERE (serial_number = :serial_number AND authority_key_identifier = :authority_key_identifier)
	  AND (ocsp_body IS NULL OR ocsp_body = '');`

	// commitRevocationCertSQL switches the certificate record (and thus
	// CRL input, which is derived from this row) to the immutable
	// journaled reason/time. The WHERE guard makes the switch a no-op
	// when the row already matches the generation, so committing is
	// idempotent and never rewrites anything with a stale value.
	commitRevocationCertSQL = `
UPDATE certificates
	SET status='revoked', reason=:reason, revoked_at=:revoked_at
	WHERE (serial_number = :serial_number AND authority_key_identifier = :authority_key_identifier)
	  AND (status <> 'revoked' OR reason <> :reason OR revoked_at IS NULL OR revoked_at <> :revoked_at);`

	selectOCSPBodySQL = `
SELECT body FROM ocsp_responses
	WHERE (serial_number = ? AND authority_key_identifier = ?);`

	markRevocationStepsSQL = `
UPDATE revocations
	SET cert_committed=:cert_committed, ocsp_committed=:ocsp_committed, updated_at=:updated_at
	WHERE (serial_number = :serial_number AND authority_key_identifier = :authority_key_identifier);`
)

var _ certdb.RevocationManager = &Accessor{}

// revocationRow is the nullable-aware storage representation of a
// revocation generation; it converts to certdb.RevocationRecord for
// callers.
type revocationRow struct {
	Serial     string         `db:"serial_number"`
	AKI        string         `db:"authority_key_identifier"`
	Reason     int            `db:"reason"`
	RevokedAt  time.Time      `db:"revoked_at"`
	OCSPBody   sql.NullString `db:"ocsp_body"`
	OCSPExpiry sql.NullTime   `db:"ocsp_expiry"`
	CertStep   bool           `db:"cert_committed"`
	OCSPStep   bool           `db:"ocsp_committed"`
	CreatedAt  time.Time      `db:"created_at"`
	UpdatedAt  time.Time      `db:"updated_at"`
}

func (r revocationRow) toRecord() certdb.RevocationRecord {
	rec := certdb.RevocationRecord{
		Serial:    r.Serial,
		AKI:       r.AKI,
		Reason:    r.Reason,
		RevokedAt: r.RevokedAt,
		CertStep:  r.CertStep,
		OCSPStep:  r.OCSPStep,
		CreatedAt: r.CreatedAt,
		UpdatedAt: r.UpdatedAt,
	}
	if r.OCSPBody.Valid {
		rec.OCSPBody = r.OCSPBody.String
	}
	if r.OCSPExpiry.Valid {
		rec.OCSPExpiry = r.OCSPExpiry.Time
	}
	return rec
}

func revocationColumns() string {
	return sqlstruct.Columns(revocationRow{})
}

// recordNotFound wraps the canonical "revocation target missing" error
// so callers see the same error class as RevokeCertificate.
func recordNotFound(what string) error {
	return cferr.Wrap(cferr.CertStoreError, cferr.RecordNotFound,
		fmt.Errorf("failed to revoke the certificate: %s not found", what))
}

// getRevocationTx loads one journal row inside a transaction.
func getRevocationTx(q sqlxQuery, serial, aki string) (certdb.RevocationRecord, error) {
	var row revocationRow
	err := q.Get(&row, fmt.Sprintf(q.Rebind(selectRevocationSQL), revocationColumns()), serial, aki)
	if err == sql.ErrNoRows {
		return certdb.RevocationRecord{}, recordNotFound("revocation record")
	}
	if err != nil {
		return certdb.RevocationRecord{}, wrapSQLError(err)
	}
	return row.toRecord(), nil
}

// sqlxQuery is the subset of *sqlx.DB/*sqlx.Tx used by the revocation
// journal statements.
type sqlxQuery interface {
	Get(dest interface{}, query string, args ...interface{}) error
	Select(dest interface{}, query string, args ...interface{}) error
	NamedExec(query string, arg interface{}) (sql.Result, error)
	Rebind(query string) string
}

// BeginRevocation implements certdb.RevocationManager. See the interface
// documentation for the full contract; in short: validate the
// certificate, then record the generation once (first writer wins),
// adopting any pre-existing revoked state instead of overwriting it.
func (d *Accessor) BeginRevocation(serial, aki string, reasonCode int) (certdb.RevocationRecord, error) {
	if err := d.checkDB(); err != nil {
		return certdb.RevocationRecord{}, err
	}

	tx, err := d.db.Beginx()
	if err != nil {
		return certdb.RevocationRecord{}, wrapSQLError(err)
	}
	defer tx.Rollback()

	// Validate serial/AKI against the certificate table and observe the
	// current status.
	var cert certdb.CertificateRecord
	err = tx.Get(&cert,
		fmt.Sprintf(tx.Rebind(selectSQL), sqlstruct.Columns(certdb.CertificateRecord{})),
		serial, aki)
	if err == sql.ErrNoRows {
		return certdb.RevocationRecord{}, recordNotFound("certificate")
	}
	if err != nil {
		return certdb.RevocationRecord{}, wrapSQLError(err)
	}

	// A generation already exists: repeat revocations are idempotent and
	// must not rewrite reason/revoked_at.
	rec, err := getRevocationTx(tx, serial, aki)
	if err == nil {
		return rec, nil
	}
	if cfErr, ok := err.(*cferr.Error); !ok ||
		cfErr.ErrorCode != int(cferr.CertStoreError)+int(cferr.RecordNotFound) {
		return certdb.RevocationRecord{}, err
	}

	now := time.Now().UTC()
	reason := reasonCode
	revokedAt := now

	// Already revoked outside the journal (legacy row, or a revoked
	// certificate inserted directly): adopt the existing reason/time so
	// the first, authoritative revocation metadata is preserved.
	if cert.Status == "revoked" {
		reason = cert.Reason
		if !cert.RevokedAt.IsZero() {
			revokedAt = cert.RevokedAt.UTC()
		}
	}

	rec = certdb.RevocationRecord{
		Serial:    serial,
		AKI:       aki,
		Reason:    reason,
		RevokedAt: revokedAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if _, err = tx.NamedExec(insertRevocationSQL, &rec); err != nil {
		// A concurrent first writer may have created the same generation.
		if existing, getErr := getRevocationTx(tx, serial, aki); getErr == nil {
			return existing, nil
		}
		return certdb.RevocationRecord{}, wrapSQLError(err)
	}

	if err = tx.Commit(); err != nil {
		return certdb.RevocationRecord{}, wrapSQLError(err)
	}
	return rec, nil
}

// SetRevocationOCSP implements certdb.RevocationManager. The first
// candidate stored for a generation wins; later candidates are ignored
// so retries and stale tasks cannot replace the prepared response or its
// revocation time.
func (d *Accessor) SetRevocationOCSP(serial, aki, body string, expiry time.Time) error {
	if err := d.checkDB(); err != nil {
		return err
	}

	now := time.Now().UTC()
	res, err := d.db.NamedExec(setRevocationOCSPSQL, &certdb.RevocationRecord{
		Serial:     serial,
		AKI:        aki,
		OCSPBody:   body,
		OCSPExpiry: expiry.UTC(),
		UpdatedAt: now,
	})
	if err != nil {
		return wrapSQLError(err)
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return wrapSQLError(err)
	}
	if affected == 0 {
		// Either a candidate is already stored (idempotent retry) or the
		// generation does not exist. Distinguish the two cases.
		if _, getErr := d.GetRevocation(serial, aki); getErr != nil {
			return getErr
		}
	}
	return nil
}

// GetRevocation implements certdb.RevocationManager.
func (d *Accessor) GetRevocation(serial, aki string) (certdb.RevocationRecord, error) {
	if err := d.checkDB(); err != nil {
		return certdb.RevocationRecord{}, err
	}
	return getRevocationTx(d.db, serial, aki)
}

// PendingRevocations implements certdb.RevocationManager.
func (d *Accessor) PendingRevocations() (recs []certdb.RevocationRecord, err error) {
	if err = d.checkDB(); err != nil {
		return nil, err
	}
	var rows []revocationRow
	err = d.db.Select(&rows,
		fmt.Sprintf(d.db.Rebind(selectPendingRevocationsSQL), revocationColumns()))
	if err != nil {
		return nil, wrapSQLError(err)
	}
	for _, row := range rows {
		recs = append(recs, row.toRecord())
	}
	return recs, nil
}

// CommitRevocation implements certdb.RevocationManager. The certificate
// record / CRL input switch and the OCSP candidate publication happen in
// one database transaction, so a failure or process exit leaves the
// previous consistent state (not revoked anywhere, or fully revoked
// everywhere) and recovery only repeats the unconfirmed switch.
func (d *Accessor) CommitRevocation(serial, aki string) error {
	if err := d.checkDB(); err != nil {
		return err
	}

	tx, err := d.db.Beginx()
	if err != nil {
		return wrapSQLError(err)
	}
	defer tx.Rollback()

	rec, err := getRevocationTx(tx, serial, aki)
	if err != nil {
		return err
	}
	if rec.Committed() {
		// Generation already visible: idempotent no-op.
		return nil
	}

	now := time.Now().UTC()
	rec.UpdatedAt = now

	// Step 1: certificate record + CRL input. The CRL endpoints read
	// revoked rows straight from the certificates table, so this single
	// update is the durable CRL-input commit.
	if !rec.CertStep {
		if _, err = tx.NamedExec(commitRevocationCertSQL, &rec); err != nil {
			return wrapSQLError(err)
		}
		rec.CertStep = true
	}

	// Step 2: publish the prepared OCSP candidate with a compare-and-swap
	// so a stale task can never restore an equal-or-newer response.
	if rec.OCSPBody != "" && !rec.OCSPStep {
		if err = publishOCSPCandidate(tx, rec); err != nil {
			return err
		}
		rec.OCSPStep = true
	}

	if _, err = tx.NamedExec(markRevocationStepsSQL, &rec); err != nil {
		return wrapSQLError(err)
	}

	if err = tx.Commit(); err != nil {
		return wrapSQLError(err)
	}
	return nil
}

// publishOCSPCandidate inserts or replaces the ocsp_responses row for a
// generation. It never downgrades an existing response:
//   - no row: insert the revoked candidate;
//   - good/unknown row (the previous state): replace with revoked;
//   - revoked row belonging to the same generation (same reason and
//     revocation time, second precision as encoded in OCSP): keep it, so
//     recommits are idempotent;
//   - revoked row from a newer generation (later revocation time): keep
//     it, so a stale candidate cannot resurrect/rewrite newer state.
func publishOCSPCandidate(tx sqlxQuery, rec certdb.RevocationRecord) error {
	var existing string
	err := tx.Get(&existing, tx.Rebind(selectOCSPBodySQL), rec.Serial, rec.AKI)
	if err == sql.ErrNoRows {
		if _, err = tx.NamedExec(insertOCSPSQL, &certdb.OCSPRecord{
			Serial: rec.Serial,
			AKI:    rec.AKI,
			Body:   rec.OCSPBody,
			Expiry: rec.OCSPExpiry.UTC(),
		}); err != nil {
			// A concurrent transaction may have inserted the row; fall
			// through to the compare-and-swap update path.
			if existingErr := tx.Get(&existing, tx.Rebind(selectOCSPBodySQL), rec.Serial, rec.AKI); existingErr != nil {
				return wrapSQLError(err)
			}
		} else {
			return nil
		}
	} else if err != nil {
		return wrapSQLError(err)
	}

	if !shouldReplaceOCSP(existing, rec) {
		return nil
	}

	if _, err = tx.NamedExec(updateOCSPSQL, &certdb.OCSPRecord{
		Serial: rec.Serial,
		AKI:    rec.AKI,
		Body:   rec.OCSPBody,
		Expiry: rec.OCSPExpiry.UTC(),
	}); err != nil {
		return wrapSQLError(err)
	}
	return nil
}

// shouldReplaceOCSP decides whether the journaled candidate may replace
// an existing OCSP response body.
func shouldReplaceOCSP(existingBody string, rec certdb.RevocationRecord) bool {
	parsed, err := stdocsp.ParseResponse([]byte(existingBody), nil)
	if err != nil {
		// Unparseable legacy row: repair it with the valid candidate.
		return true
	}
	if parsed.Status != stdocsp.Revoked {
		// Previous state was good/unknown: the revocation switch wins.
		return true
	}
	// Existing response is revoked. Same generation (reason + revocation
	// time, at the second precision OCSP encodes) keeps the first
	// response; a newer revocation time also keeps it. Only an older
	// revocation may be replaced, which a first-writer-wins journal can
	// normally never produce.
	existingAt := parsed.RevokedAt.UTC().Truncate(time.Second)
	candidateAt := rec.RevokedAt.UTC().Truncate(time.Second)
	if existingAt.After(candidateAt) {
		return false
	}
	if existingAt.Equal(candidateAt) {
		return false
	}
	return true
}
