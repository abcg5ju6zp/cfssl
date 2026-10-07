package ocsprefresh

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/ocsp"
	cryptoocsp "golang.org/x/crypto/ocsp"
)

// tempSQLiteDB copies the committed SQLite schema into a temp file so tests
// can mutate the database without affecting other tests.
const testAKI = "fake_aki"
func tempSQLiteDB(t *testing.T) (*sql.Accessor, interface{ Close() error }) {
	src, err := os.ReadFile("../../certdb/testdb/certstore_development.db")
	if err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(t.TempDir(), "test.db")
	if err = os.WriteFile(dbPath, src, 0644); err != nil {
		t.Fatal(err)
	}
	db := testdb.SQLiteDB(dbPath)
	return sql.NewAccessor(db), db
}

func testResponder(t *testing.T) *x509.Certificate {
	pem, err := os.ReadFile("../../ocsp/testdata/server.crt")
	if err != nil {
		t.Fatal(err)
	}
	responder, err := helpers.ParseCertificatePEM(pem)
	if err != nil {
		t.Fatal(err)
	}
	return responder
}

func testRealSigner(t *testing.T) ocsp.Signer {
	signer, err := ocsp.NewSignerFromFile(
		"../../ocsp/testdata/ca.pem",
		"../../ocsp/testdata/server.crt",
		"../../ocsp/testdata/server.key",
		helpers.OneDay)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

type failSigner struct{}

func (failSigner) Sign(req ocsp.SignRequest) ([]byte, error) {
	return nil, errors.New("simulated signer failure")
}

// TestOCSPRefreshFailureAndResume verifies that when a candidate cannot be
// generated the old response stays available, the certificate remains
// pending, and the next run only continues that certificate.
func TestOCSPRefreshFailureAndResume(t *testing.T) {
	dbAccessor, db := tempSQLiteDB(t)
	defer db.Close()

	certPEM, err := os.ReadFile("../../ocsp/testdata/cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := helpers.ParseCertificatePEM(certPEM)
	if err != nil {
		t.Fatal(err)
	}

	certRecord := certdb.CertificateRecord{
		Serial: cert.SerialNumber.String(),
		AKI:    hex.EncodeToString(cert.AuthorityKeyId),
		Expiry: time.Now().AddDate(1, 0, 0),
		PEM:    string(certPEM),
		Status: "good",
	}
	if err = dbAccessor.InsertCertificate(certRecord); err != nil {
		t.Fatal(err)
	}

	// Seed the previous (still valid) OCSP response.
	if err = dbAccessor.InsertOCSP(certdb.OCSPRecord{
		Serial: certRecord.Serial,
		AKI:    certRecord.AKI,
		Body:   "old-ocsp-response",
		Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// First run: signer fails.
	err = Refresh(dbAccessor, failSigner{}, testResponder(t), helpers.OneDay)
	if err == nil {
		t.Fatal("expected refresh to report unconfirmed certificates")
	}

	records, err := dbAccessor.GetOCSP(certRecord.Serial, certRecord.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Body != "old-ocsp-response" {
		t.Fatalf("old OCSP response must remain available, got %+v", records)
	}

	pending, err := dbAccessor.GetPendingOCSPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Body != "" {
		t.Fatalf("expected one empty pending slot, got %+v", pending)
	}

	// Second run: signer works; only the pending certificate is processed.
	if err = Refresh(dbAccessor, testRealSigner(t), testResponder(t), helpers.OneDay); err != nil {
		t.Fatal(err)
	}

	records, err = dbAccessor.GetOCSP(certRecord.Serial, certRecord.AKI)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatal("expected one OCSP response")
	}
	parsed, err := cryptoocsp.ParseResponse([]byte(records[0].Body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Status != cryptoocsp.Good {
		t.Fatal("expected good status")
	}
	if records[0].GeneratedAt.IsZero() {
		t.Fatal("expected non-zero generation timestamp")
	}

	pending, err = dbAccessor.GetPendingOCSPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending rows after confirmation, got %+v", pending)
	}
}

// TestOCSPRefreshNoRollback verifies that a delayed candidate cannot
// replace a response committed by a more recent run.
func TestOCSPRefreshNoRollback(t *testing.T) {
	dbAccessor, db := tempSQLiteDB(t)
	defer db.Close()

	const serial, aki = "rollback-serial", "rollback-aki"
	if err := dbAccessor.InsertCertificate(certdb.CertificateRecord{
		Serial: serial,
		AKI:    aki,
		Expiry: time.Now().AddDate(1, 0, 0),
		PEM:    "fake cert data",
		Status: "good",
	}); err != nil {
		t.Fatal(err)
	}

	// A more recent refresh already committed a response generated in
	// the future relative to the stale candidate.
	committedAt := time.Now().Add(time.Hour)
	staleAt := time.Now()
	if err := dbAccessor.InsertPendingOCSP(certdb.OCSPRecord{Serial: serial, AKI: aki}); err != nil {
		t.Fatal(err)
	}
	if err := dbAccessor.ConfirmOCSPs([]certdb.OCSPRecord{{
		Serial:      serial,
		AKI:         aki,
		Body:        "newer-response",
		Expiry:      committedAt.Add(helpers.OneDay),
		GeneratedAt: committedAt,
	}}); err != nil {
		t.Fatal(err)
	}

	// An older wave comes back and tries to confirm its candidate.
	if err := dbAccessor.InsertPendingOCSP(certdb.OCSPRecord{Serial: serial, AKI: aki}); err != nil {
		t.Fatal(err)
	}
	if err := dbAccessor.UpdatePendingOCSP(certdb.OCSPRecord{
		Serial:      serial,
		AKI:         aki,
		Body:        "older-candidate",
		Expiry:      staleAt.Add(helpers.OneDay),
		GeneratedAt: staleAt,
	}); err != nil {
		t.Fatal(err)
	}
	if err := dbAccessor.ConfirmOCSPs([]certdb.OCSPRecord{{
		Serial:      serial,
		AKI:         aki,
		Body:        "older-candidate",
		Expiry:      staleAt.Add(helpers.OneDay),
		GeneratedAt: staleAt,
	}}); err != nil {
		t.Fatal(err)
	}

	records, err := dbAccessor.GetOCSP(serial, aki)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Body != "newer-response" {
		t.Fatalf("newer response must be preserved, got %+v", records)
	}

	pending, err := dbAccessor.GetPendingOCSPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("pending slot must be cleared even when candidate is skipped, got %+v", pending)
	}
}

// TestConfirmOCSPsBatchAndInsert checks that a batch inserts responses that
// have no committed row yet, and that re-confirming the same generation is
// a no-op rather than a rollback.
func TestConfirmOCSPsBatchAndInsert(t *testing.T) {
	dbAccessor, db := tempSQLiteDB(t)
	defer db.Close()

	generatedAt := time.Now()
	var batch []certdb.OCSPRecord
	for i := 0; i < 3; i++ {
		serial := "batch-serial-" + string(rune('a'+i))
		if err := dbAccessor.InsertCertificate(certdb.CertificateRecord{
			Serial: serial,
			AKI:    testAKI,
			Expiry: time.Now().AddDate(1, 0, 0),
			PEM:    "fake cert data",
			Status: "good",
		}); err != nil {
			t.Fatal(err)
		}
		if err := dbAccessor.InsertPendingOCSP(certdb.OCSPRecord{Serial: serial, AKI: testAKI}); err != nil {
			t.Fatal(err)
		}
		batch = append(batch, certdb.OCSPRecord{
			Serial:      serial,
			AKI:         testAKI,
			Body:        "candidate-" + string(rune('a'+i)),
			Expiry:      generatedAt.Add(helpers.OneDay),
			GeneratedAt: generatedAt,
		})
	}

	if err := dbAccessor.ConfirmOCSPs(batch); err != nil {
		t.Fatal(err)
	}

	for i, rec := range batch {
		got, err := dbAccessor.GetOCSP(rec.Serial, rec.AKI)
		if err != nil {
			t.Fatal(err)
		}
		want := "candidate-" + string(rune('a'+i))
		if len(got) != 1 || got[0].Body != want {
			t.Fatalf("expected %s, got %+v", want, got)
		}
	}

	// Re-confirming the same (equal) generation must not change anything.
	if err := dbAccessor.ConfirmOCSPs(batch); err != nil {
		t.Fatal(err)
	}
	for _, rec := range batch {
		got, err := dbAccessor.GetOCSP(rec.Serial, rec.AKI)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Body != rec.Body {
			t.Fatalf("response must be unchanged, got %+v", got)
		}
	}

	pending, err := dbAccessor.GetPendingOCSPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending rows, got %+v", pending)
	}
}

// TestOCSPRefreshEmptyDB verifies empty-database behavior: no error, no
// responses, no leftover pending rows.
func TestOCSPRefreshEmptyDB(t *testing.T) {
	dbAccessor, db := tempSQLiteDB(t)
	defer db.Close()

	if err := Refresh(dbAccessor, failSigner{}, testResponder(t), helpers.OneDay); err != nil {
		t.Fatal(err)
	}

	ocsps, err := dbAccessor.GetUnexpiredOCSPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ocsps) != 0 {
		t.Fatalf("expected no OCSP responses, got %+v", ocsps)
	}

	pending, err := dbAccessor.GetPendingOCSPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no pending rows, got %+v", pending)
	}
}
