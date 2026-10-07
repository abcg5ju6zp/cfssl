package certdb

import "time"

// RevocationRecord is one durable, resumable revocation generation. It
// is stored in the revocations table and keyed by (serial, AKI), exactly
// like the certificate it revokes.
//
// The first revocation of a certificate creates the row and fixes the
// authoritative revocation reason and time forever: repeat revocations
// read the same row back instead of overwriting those fields, which
// makes retries idempotent. The signed OCSP candidate is stored before
// any state becomes visible, so a crash after the candidate is prepared
// but before it is published never loses or re-derives the response.
// Steps records how much of the generation has been committed so that
// recovery only resumes unconfirmed steps.
type RevocationRecord struct {
	Serial    string    `db:"serial_number"`
	AKI       string    `db:"authority_key_identifier"`
	Reason    int       `db:"reason"`
	RevokedAt time.Time `db:"revoked_at"`

	// OCSPBody/OCSPExpiry hold the signed OCSP response candidate. An
	// empty OCSPBody means this generation carries no OCSP candidate
	// (the handler had no OCSP signer).
	OCSPBody   string    `db:"ocsp_body"`
	OCSPExpiry time.Time `db:"ocsp_expiry"`
	CertStep   bool      `db:"cert_committed"`
	OCSPStep   bool      `db:"ocsp_committed"`
	CreatedAt  time.Time `db:"created_at"`
	UpdatedAt  time.Time `db:"updated_at"`
}

// Committed reports whether every step belonging to this generation has
// been committed. A generation without an OCSP candidate is complete as
// soon as the certificate/CRL step is committed.
func (r RevocationRecord) Committed() bool {
	if !r.CertStep {
		return false
	}
	if r.OCSPBody != "" && !r.OCSPStep {
		return false
	}
	return true
}

// Pending reports whether the generation still has unconfirmed work that
// recovery must resume.
func (r RevocationRecord) Pending() bool {
	return !r.Committed()
}

// RevocationManager is an optional extension of Accessor implemented by
// backends that can commit a revocation as a single resumable
// generation. Code driving revocation should type-assert an Accessor to
// RevocationManager and fall back to the legacy per-call behaviour when
// the capability is unavailable, so existing Accessor implementations
// keep working unchanged.
type RevocationManager interface {
	// BeginRevocation validates the certificate (it must exist for the
	// serial/AKI pair) and durably records revocation intent.
	//
	// The first call for a given serial/AKI creates the generation with
	// the given reason and a fixed revocation time. Certificates that
	// are already marked revoked outside the journal (legacy rows or
	// inserts of revoked certificates) are adopted with their existing
	// reason/time instead of being rewritten. Later calls are
	// idempotent and return the stored generation, ignoring the supplied
	// reason so retries can never overwrite the committed reason/time.
	BeginRevocation(serial, aki string, reasonCode int) (RevocationRecord, error)

	// SetRevocationOCSP stores the signed OCSP response candidate for a
	// pending generation. It is first-writer-wins: a candidate already
	// stored for the generation is left untouched, so a retried or stale
	// signing task cannot replace the prepared response.
	SetRevocationOCSP(serial, aki, body string, expiry time.Time) error

	// CommitRevocation makes one generation visible atomically: the
	// certificate record is updated with the journaled (immutable)
	// reason and revocation time, which simultaneously makes the serial
	// part of CRL input, and the stored OCSP candidate is published.
	// Either every step commits or none does. Committing an already
	// committed generation is a no-op; a stale candidate can never
	// downgrade an equal-or-newer published OCSP response or restore a
	// revoked certificate.
	CommitRevocation(serial, aki string) error

	// GetRevocation returns the generation recorded for serial/AKI.
	GetRevocation(serial, aki string) (RevocationRecord, error)

	// PendingRevocations returns generations that still have
	// unconfirmed steps, for recovery after a failure or process exit.
	PendingRevocations() ([]RevocationRecord, error)
}
