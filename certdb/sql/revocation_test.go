package sql

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/testdb"
	cferr "github.com/cloudflare/cfssl/errors"

	stdocsp "golang.org/x/crypto/ocsp"
)

func newRevocationTestAccessor(t *testing.T) (*Accessor, func()) {
	db := testdb.SQLiteDB(sqliteDBFile)
	tr := func() { testdb.Truncate(db) }
	tr()
	return NewAccessor(db), tr
}

func insertGoodCertForRevocation(t *testing.T, d *Accessor, serial, status string, reason int, revokedAt time.Time) {
	cr := certdb.CertificateRecord{
		Serial:    serial,
		AKI:       fakeAKI,
		CALabel:   "default",
		Status:    status,
		Reason:    reason,
		Expiry:    time.Now().Add(time.Hour),
		RevokedAt: revokedAt,
		PEM:       "fake cert data",
	}
	if err := d.InsertCertificate(cr); err != nil {
		t.Fatal(err)
	}
}

func TestBeginRevocationUnknownCertificate(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	_, err := d.BeginRevocation("missing", fakeAKI, stdocsp.KeyCompromise)
	if err == nil {
		t.Fatal("expected error revoking unknown certificate")
	}
	cfErr, ok := err.(*cferr.Error)
	if !ok || cfErr.ErrorCode != int(cferr.CertStoreError)+int(cferr.RecordNotFound) {
		t.Fatalf("expected RecordNotFound, got %v", err)
	}
}

func TestRevocationGenerationCertOnly(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	insertGoodCertForRevocation(t, d, "gen1", "good", 0, time.Time{})

	rec, err := d.BeginRevocation("gen1", fakeAKI, stdocsp.CACompromise)
	if err != nil {
		t.Fatal(err)
	}
	if rec.CertStep || rec.OCSPStep || rec.OCSPBody != "" {
		t.Fatalf("fresh generation should have no committed steps: %+v", rec)
	}
	if rec.Reason != stdocsp.CACompromise || rec.RevokedAt.IsZero() {
		t.Fatalf("generation should record reason and time: %+v", rec)
	}

	pending, err := d.PendingRevocations()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Serial != "gen1" {
		t.Fatalf("expected one pending generation, got %+v", pending)
	}

	if err := d.CommitRevocation("gen1", fakeAKI); err != nil {
		t.Fatal(err)
	}

	certs, err := d.GetCertificate("gen1", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 || certs[0].Status != "revoked" || certs[0].Reason != stdocsp.CACompromise {
		t.Fatalf("certificate not switched by generation commit: %+v", certs)
	}
	if !roughlySameTime(certs[0].RevokedAt, rec.RevokedAt) {
		t.Fatalf("revoked_at should come from the journal: %v vs %v", certs[0].RevokedAt, rec.RevokedAt)
	}

	committed, err := d.GetRevocation("gen1", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	if !committed.Committed() || !committed.CertStep {
		t.Fatalf("generation should be committed: %+v", committed)
	}
	if pending, err := d.PendingRevocations(); err != nil || len(pending) != 0 {
		t.Fatalf("expected no pending generations, got %+v %v", pending, err)
	}

	// Re-committing is an idempotent no-op.
	if err := d.CommitRevocation("gen1", fakeAKI); err != nil {
		t.Fatal(err)
	}
}

func TestRepeatRevocationKeepsFirstReasonAndTime(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	insertGoodCertForRevocation(t, d, "gen2", "good", 0, time.Time{})

	first, err := d.BeginRevocation("gen2", fakeAKI, stdocsp.KeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CommitRevocation("gen2", fakeAKI); err != nil {
		t.Fatal(err)
	}

	// A later, different revocation request must not rewrite anything.
	again, err := d.BeginRevocation("gen2", fakeAKI, stdocsp.CessationOfOperation)
	if err != nil {
		t.Fatal(err)
	}
	if again.Reason != stdocsp.KeyCompromise || !again.RevokedAt.Equal(first.RevokedAt) {
		t.Fatalf("repeat revocation must adopt the first generation: first=%+v again=%+v", first, again)
	}
	if err := d.CommitRevocation("gen2", fakeAKI); err != nil {
		t.Fatal(err)
	}

	certs, err := d.GetCertificate("gen2", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	if certs[0].Reason != stdocsp.KeyCompromise ||
		!roughlySameTime(certs[0].RevokedAt, first.RevokedAt) {
		t.Fatalf("first reason/time must survive retries: %+v", certs[0])
	}
}

func TestBeginAdoptsPreexistingRevocation(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	originalTime := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	insertGoodCertForRevocation(t, d, "gen3", "revoked", stdocsp.AffiliationChanged, originalTime)

	// Requesting "revocation" of an already-revoked (legacy / directly
	// inserted) certificate adopts, not rewrites, its reason/time.
	rec, err := d.BeginRevocation("gen3", fakeAKI, stdocsp.KeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Reason != stdocsp.AffiliationChanged {
		t.Fatalf("should adopt existing reason, got %d", rec.Reason)
	}
	if !rec.RevokedAt.Equal(originalTime) {
		t.Fatalf("should adopt existing revoked_at, got %v want %v", rec.RevokedAt, originalTime)
	}
	if err := d.CommitRevocation("gen3", fakeAKI); err != nil {
		t.Fatal(err)
	}
	certs, err := d.GetCertificate("gen3", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	if certs[0].Reason != stdocsp.AffiliationChanged ||
		!roughlySameTime(certs[0].RevokedAt, originalTime) {
		t.Fatalf("adopted revocation must be stable: %+v", certs[0])
	}
}

// ocspTestCA builds a self-signed issuer, a leaf certificate and the
// signing key needed to produce OCSP responses in tests.
type ocspTestCA struct {
	issuer *x509.Certificate
	leaf   *x509.Certificate
	key    *rsa.PrivateKey
}

func newOCSPTestCA(t *testing.T) *ocspTestCA {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"cfssl test"}},
		AuthorityKeyId:        []byte{1, 2, 3, 4},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber:   big.NewInt(4242),
		Subject:        pkix.Name{Organization: []string{"cfssl test leaf"}},
		AuthorityKeyId: []byte{1, 2, 3, 4},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, &leafTemplate, issuer, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}
	return &ocspTestCA{issuer: issuer, leaf: leaf, key: key}
}

func (ca *ocspTestCA) ocspResponse(t *testing.T, status int, reason int, revokedAt time.Time) []byte {
	t.Helper()
	template := stdocsp.Response{
		Status:       status,
		SerialNumber: ca.leaf.SerialNumber,
		ThisUpdate:   time.Now().Truncate(time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
	}
	if status == stdocsp.Revoked {
		template.RevokedAt = revokedAt
		template.RevocationReason = reason
	}
	resp, err := stdocsp.CreateResponse(ca.issuer, ca.issuer, template, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestOCSPCandidateFirstWriterWinsAndCommits(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	ca := newOCSPTestCA(t)
	insertGoodCertForRevocation(t, d, "gen4", "good", 0, time.Time{})

	rec, err := d.BeginRevocation("gen4", fakeAKI, stdocsp.KeyCompromise)
	if err != nil {
		t.Fatal(err)
	}

	candidate := ca.ocspResponse(t, stdocsp.Revoked, stdocsp.KeyCompromise, rec.RevokedAt)
	expiry := time.Now().Add(time.Hour)
	if err := d.SetRevocationOCSP("gen4", fakeAKI, string(candidate), expiry); err != nil {
		t.Fatal(err)
	}

	// A retried/stale signing task must not replace the candidate.
	stale := ca.ocspResponse(t, stdocsp.Revoked, stdocsp.CACompromise, rec.RevokedAt.Add(time.Minute))
	if err := d.SetRevocationOCSP("gen4", fakeAKI, string(stale), expiry.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	stored, err := d.GetRevocation("gen4", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	if stored.OCSPBody != string(candidate) {
		t.Fatal("SetRevocationOCSP must be first-writer-wins")
	}

	// Before the switch nothing is visible: certificate is still good and
	// no OCSP row exists.
	certs, _ := d.GetCertificate("gen4", fakeAKI)
	if certs[0].Status != "good" {
		t.Fatal("certificate must stay good until the generation commits")
	}
	if rows, _ := d.GetOCSP("gen4", fakeAKI); len(rows) != 0 {
		t.Fatal("no OCSP response may exist before commit")
	}

	if err := d.CommitRevocation("gen4", fakeAKI); err != nil {
		t.Fatal(err)
	}

	rows, err := d.GetOCSP("gen4", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Body != string(candidate) {
		t.Fatalf("candidate should be published exactly once, got %d rows", len(rows))
	}
	parsed, err := stdocsp.ParseResponse([]byte(rows[0].Body), nil)
	if err != nil || parsed.Status != stdocsp.Revoked || parsed.RevocationReason != stdocsp.KeyCompromise {
		t.Fatalf("published OCSP should be the revoked candidate: %v %v", parsed, err)
	}

	// Recommit keeps the first, same-generation response.
	if err := d.CommitRevocation("gen4", fakeAKI); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.GetOCSP("gen4", fakeAKI)
	if len(rows) != 1 || rows[0].Body != string(candidate) {
		t.Fatal("recommit must not replace the same-generation response")
	}
}

func TestCommitReplacesGoodOCSPButKeepsNewerRevocation(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	ca := newOCSPTestCA(t)

	// Existing "good" response (previous consistent state) must be
	// replaced by the revoked switch.
	insertGoodCertForRevocation(t, d, "gen5", "good", 0, time.Time{})
	good := ca.ocspResponse(t, stdocsp.Good, 0, time.Time{})
	if err := d.InsertOCSP(certdb.OCSPRecord{
		Serial: "gen5", AKI: fakeAKI, Body: string(good), Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	rec, err := d.BeginRevocation("gen5", fakeAKI, stdocsp.Unspecified)
	if err != nil {
		t.Fatal(err)
	}
	candidate := ca.ocspResponse(t, stdocsp.Revoked, stdocsp.Unspecified, rec.RevokedAt)
	if err := d.SetRevocationOCSP("gen5", fakeAKI, string(candidate), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := d.CommitRevocation("gen5", fakeAKI); err != nil {
		t.Fatal(err)
	}
	rows, _ := d.GetOCSP("gen5", fakeAKI)
	if len(rows) != 1 || rows[0].Body != string(candidate) {
		t.Fatal("revoked switch must replace a good OCSP response")
	}

	// A stale candidate (older revocation time) must not overwrite a
	// newer revoked response already present.
	insertGoodCertForRevocation(t, d, "gen6", "revoked", stdocsp.KeyCompromise, time.Now().Truncate(time.Second))
	newer := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	newerBody := ca.ocspResponse(t, stdocsp.Revoked, stdocsp.KeyCompromise, newer)
	if err := d.InsertOCSP(certdb.OCSPRecord{
		Serial: "gen6", AKI: fakeAKI, Body: string(newerBody), Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	// Begin adopts the existing revoked time, then an old candidate is
	// attached and committed: the newer response must survive.
	rec6, err := d.BeginRevocation("gen6", fakeAKI, stdocsp.KeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	oldCandidate := ca.ocspResponse(t, stdocsp.Revoked, stdocsp.KeyCompromise, rec6.RevokedAt)
	if err := d.SetRevocationOCSP("gen6", fakeAKI, string(oldCandidate), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := d.CommitRevocation("gen6", fakeAKI); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.GetOCSP("gen6", fakeAKI)
	if len(rows) != 1 || rows[0].Body != string(newerBody) {
		t.Fatal("a stale generation must not overwrite a newer revoked OCSP response")
	}
}

func TestOCSPBackfillAfterCertOnlyCommit(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	ca := newOCSPTestCA(t)
	insertGoodCertForRevocation(t, d, "gen7", "good", 0, time.Time{})

	// First generation is committed without an OCSP candidate.
	rec, err := d.BeginRevocation("gen7", fakeAKI, stdocsp.KeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.CommitRevocation("gen7", fakeAKI); err != nil {
		t.Fatal(err)
	}
	if pending, _ := d.PendingRevocations(); len(pending) != 0 {
		t.Fatalf("cert-only generation should be complete, got %+v", pending)
	}

	// A later handler with a signer backfills the candidate; the
	// generation becomes pending again and commits the OCSP step without
	// touching the first revocation time.
	candidate := ca.ocspResponse(t, stdocsp.Revoked, stdocsp.KeyCompromise, rec.RevokedAt)
	if err := d.SetRevocationOCSP("gen7", fakeAKI, string(candidate), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	pending, err := d.PendingRevocations()
	if err != nil || len(pending) != 1 || pending[0].Serial != "gen7" {
		t.Fatalf("backfilled generation should be pending its OCSP step: %+v %v", pending, err)
	}
	if err := d.CommitRevocation("gen7", fakeAKI); err != nil {
		t.Fatal(err)
	}
	rows, err := d.GetOCSP("gen7", fakeAKI)
	if err != nil || len(rows) != 1 || rows[0].Body != string(candidate) {
		t.Fatalf("backfilled candidate should be published: %+v %v", rows, err)
	}
	certs, _ := d.GetCertificate("gen7", fakeAKI)
	if !roughlySameTime(certs[0].RevokedAt, rec.RevokedAt) {
		t.Fatal("backfill must not move the original revocation time")
	}
	if pending, _ := d.PendingRevocations(); len(pending) != 0 {
		t.Fatalf("generation should be complete again, got %+v", pending)
	}
}

func TestUpsertOCSPIfCurrent(t *testing.T) {
	d, _ := newRevocationTestAccessor(t)
	insertGoodCertForRevocation(t, d, "u1", "good", 0, time.Time{})

	body := "good-body"
	if err := d.UpsertOCSPIfCurrent("u1", fakeAKI, body, time.Now().Add(time.Hour), "good"); err != nil {
		t.Fatal(err)
	}
	rows, err := d.GetOCSP("u1", fakeAKI)
	if err != nil || len(rows) != 1 || rows[0].Body != body {
		t.Fatalf("guarded upsert should write when status matches: %+v %v", rows, err)
	}

	// Certificate revoked in the meantime: a stale "good" write must be
	// skipped rather than restoring the certificate.
	if err := d.RevokeCertificate("u1", fakeAKI, stdocsp.KeyCompromise); err != nil {
		t.Fatal(err)
	}
	if err := d.UpsertOCSPIfCurrent("u1", fakeAKI, "stale-good", time.Now().Add(2*time.Hour), "good"); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.GetOCSP("u1", fakeAKI)
	if len(rows) != 1 || rows[0].Body != body {
		t.Fatalf("stale good response must not be written after revocation: %+v", rows)
	}

	// A response matching the current status still writes.
	if err := d.UpsertOCSPIfCurrent("u1", fakeAKI, "revoked-body", time.Now().Add(2*time.Hour), "revoked"); err != nil {
		t.Fatal(err)
	}
	rows, _ = d.GetOCSP("u1", fakeAKI)
	if len(rows) != 1 || rows[0].Body != "revoked-body" {
		t.Fatalf("matching revoked response should be written: %+v", rows)
	}
}
