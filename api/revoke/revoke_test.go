package revoke

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/certdb/testdb"
	"github.com/cloudflare/cfssl/ocsp"

	stdocsp "golang.org/x/crypto/ocsp"
)

const (
	fakeAKI = "fake aki"
)

func prepDB() (certdb.Accessor, error) {
	db := testdb.SQLiteDB("../../certdb/testdb/certstore_development.db")
	expirationTime := time.Now().AddDate(1, 0, 0)
	var cert = certdb.CertificateRecord{
		Serial: "1",
		AKI:    fakeAKI,
		Expiry: expirationTime,
		PEM:    "unexpired cert",
	}

	dbAccessor := sql.NewAccessor(db)
	err := dbAccessor.InsertCertificate(cert)
	if err != nil {
		return nil, err
	}

	return dbAccessor, nil
}

func testRevokeCert(t *testing.T, dbAccessor certdb.Accessor, serial, aki, reason string) (resp *http.Response, body []byte) {
	ts := httptest.NewServer(NewHandler(dbAccessor))
	defer ts.Close()

	obj := map[string]interface{}{}

	obj["serial"] = serial
	obj["authority_key_id"] = aki

	if reason != "" {
		obj["reason"] = reason
	}

	blob, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestInvalidRevocation(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, _ := testRevokeCert(t, dbAccessor, "", "", "")

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatal("expected bad request response")
	}
}

func TestRevocation(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	resp, body := testRevokeCert(t, dbAccessor, "1", fakeAKI, "5")

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	certs, err := dbAccessor.GetCertificate("1", fakeAKI)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.Status != "revoked" || cert.Reason != 5 {
		t.Fatal("cert was not correctly revoked")
	}
}

// TestOCSPGeneration tests that revoking a certificate (when the
// request handler has an OCSP response signer) generates an
// appropriate OCSP response in the certdb.
func TestOCSPGeneration(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	// 1. Generate a CA certificate to serve as the signing certificate.
	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := x509.Certificate{
		SerialNumber: issuerSerial,
		Subject: pkix.Name{
			Organization: []string{"cfssl unit test"},
		},
		AuthorityKeyId:        []byte{42, 42, 42, 42},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}

	// 2. Generate a certificate signed by the CA certificate to revoke.
	revokedSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	revokedTemplate := x509.Certificate{
		SerialNumber: revokedSerial,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}
	revokedBytes, err := x509.CreateCertificate(rand.Reader, &revokedTemplate, issuer, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}

	revoked := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: revokedBytes,
	})

	revokedAKI := hex.EncodeToString(revokedTemplate.AuthorityKeyId)
	revokedSerialStr := revokedSerial.Text(16)

	// 3. Generate a certificate to use as the responder certificate.
	responderSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	responderTemplate := x509.Certificate{
		SerialNumber: responderSerial,
		Subject: pkix.Name{
			Organization: []string{"Cornell CS 5152 Responder"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 43},
	}
	responderBytes, err := x509.CreateCertificate(rand.Reader, &responderTemplate, &responderTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	responder, err := x509.ParseCertificate(responderBytes)
	if err != nil {
		t.Fatal(err)
	}

	// 4. Create the OCSP signer
	signer, err := ocsp.NewSigner(issuer, responder, privKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 5. Spin up the test server
	// 5a. Prepare the DB
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}
	expirationTime := time.Now().AddDate(1, 0, 0)
	cr := certdb.CertificateRecord{
		Serial: revokedSerialStr,
		AKI:    revokedAKI,
		Expiry: expirationTime,
		PEM:    string(revoked),
	}
	if err := dbAccessor.InsertCertificate(cr); err != nil {
		t.Fatal(err)
	}

	// 5b. Start the test server
	ts := httptest.NewServer(NewOCSPHandler(dbAccessor, signer))
	defer ts.Close()

	// 6. Prepare the revocation request
	obj := map[string]interface{}{}

	obj["serial"] = revokedSerialStr
	obj["authority_key_id"] = revokedAKI
	obj["reason"] = "unspecified"

	blob, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}

	// Get the original number of OCSP responses
	ocspsBefore, _ := dbAccessor.GetOCSP(revokedSerialStr, revokedAKI)
	ocspCountBefore := len(ocspsBefore)

	// 7. Send the revocation request
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Fatal("unexpected HTTP status code; expected OK", string(body))
	}
	message := new(api.Response)
	err = json.Unmarshal(body, message)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	// 8. Make sure the certificate record was updated
	certs, err := dbAccessor.GetCertificate(revokedSerialStr, revokedAKI)
	if err != nil {
		t.Fatal("failed to get certificate ", err)
	}
	if len(certs) != 1 {
		t.Fatal("failed to get one certificate")
	}

	cert := certs[0]

	if cert.Status != "revoked" || cert.Reason != stdocsp.Unspecified {
		t.Fatal("cert was not correctly revoked")
	}

	// 9. Make sure there is an OCSP record
	ocsps, err := dbAccessor.GetOCSP(revokedSerialStr, revokedAKI)
	if err != nil {
		t.Fatal("failed to get OCSP responses ", err)
	}

	if len(ocsps) == 0 {
		t.Fatal("No OCSP response generated")
	}

	if len(ocsps) <= ocspCountBefore {
		t.Fatal("No new OCSP response found")
	}
}

type revokeTestCA struct {
	issuer *x509.Certificate
	leaf   *x509.Certificate
	key    *rsa.PrivateKey
	signer ocsp.Signer
	leafPEM []byte
	serial string
	aki    string
}

func newRevokeTestCA(t *testing.T) *revokeTestCA {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serialNumberRange := new(big.Int).Lsh(big.NewInt(1), 128)

	issuerSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := x509.Certificate{
		SerialNumber: issuerSerial,
		Subject: pkix.Name{
			Organization: []string{"cfssl unit test"},
		},
		AuthorityKeyId:        []byte{42, 42, 42, 42},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	issuerBytes, err := x509.CreateCertificate(rand.Reader, &issuerTemplate, &issuerTemplate, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerBytes)
	if err != nil {
		t.Fatal(err)
	}

	leafSerial, err := rand.Int(rand.Reader, serialNumberRange)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber: leafSerial,
		Subject: pkix.Name{
			Organization: []string{"cfssl unit test leaf"},
		},
		AuthorityKeyId: []byte{42, 42, 42, 42},
	}
	leafBytes, err := x509.CreateCertificate(rand.Reader, &leafTemplate, issuer, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafBytes)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := ocsp.NewSigner(issuer, issuer, privKey, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	return &revokeTestCA{
		issuer: issuer,
		leaf:   leaf,
		key:    privKey,
		signer: signer,
		leafPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: leafBytes,
		}),
		serial: leafSerial.Text(16),
		aki:    hex.EncodeToString(leafTemplate.AuthorityKeyId),
	}
}

func insertLeaf(t *testing.T, dbAccessor certdb.Accessor, ca *revokeTestCA, status string) {
	t.Helper()
	cr := certdb.CertificateRecord{
		Serial: ca.serial,
		AKI:    ca.aki,
		Expiry: time.Now().AddDate(1, 0, 0),
		PEM:    string(ca.leafPEM),
		Status: status,
	}
	if err := dbAccessor.InsertCertificate(cr); err != nil {
		t.Fatal(err)
	}
}

// TestIdempotentRevocation verifies that revoking an already-revoked
// certificate succeeds and never rewrites the first revocation's reason
// or time, even when the retry requests a different reason.
func TestIdempotentRevocation(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}

	if resp, _ := testRevokeCert(t, dbAccessor, "1", fakeAKI, "5"); resp.StatusCode != http.StatusOK {
		t.Fatal("first revocation should succeed")
	}
	certs, err := dbAccessor.GetCertificate("1", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	first := certs[0]
	if first.Status != "revoked" || first.Reason != 5 {
		t.Fatalf("unexpected first revocation: %+v", first)
	}

	// Retry with a different reason code.
	if resp, body := testRevokeCert(t, dbAccessor, "1", fakeAKI, "1"); resp.StatusCode != http.StatusOK {
		t.Fatal("repeat revocation should be idempotent and succeed: ", string(body))
	}
	certs, err = dbAccessor.GetCertificate("1", fakeAKI)
	if err != nil {
		t.Fatal(err)
	}
	again := certs[0]
	if again.Reason != 5 {
		t.Fatalf("repeat revocation must not overwrite reason, got %d", again.Reason)
	}
	if !again.RevokedAt.Equal(first.RevokedAt) {
		t.Fatalf("repeat revocation must not overwrite revoked_at: %v vs %v",
			again.RevokedAt, first.RevokedAt)
	}

	// The serial must also appear in CRL input exactly once.
	revoked, err := dbAccessor.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, c := range revoked {
		if c.Serial == "1" && c.AKI == fakeAKI {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("CRL input should contain the serial once, got %d", count)
	}
}

// TestRevocationUnknownSerial keeps the historical failure behaviour for
// serial/AKI pairs that do not identify a certificate.
func TestRevocationUnknownSerial(t *testing.T) {
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}
	if resp, _ := testRevokeCert(t, dbAccessor, "does-not-exist", fakeAKI, "0"); resp.StatusCode == http.StatusOK {
		t.Fatal("revoking an unknown serial must not succeed")
	}
}

// TestRevocationAtomicOCSPSwitch verifies that the revoked OCSP response
// replaces a pre-existing good response together with the certificate
// switch, and repeated revocations publish exactly one stable response.
func TestRevocationAtomicOCSPSwitch(t *testing.T) {
	ca := newRevokeTestCA(t)
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}
	insertLeaf(t, dbAccessor, ca, "good")

	// Pre-existing "good" OCSP response, as ocsprefresh would create.
	goodResp, err := ca.signer.Sign(ocsp.SignRequest{Certificate: ca.leaf, Status: "good"})
	if err != nil {
		t.Fatal(err)
	}
	if err := dbAccessor.InsertOCSP(certdb.OCSPRecord{
		Serial: ca.serial,
		AKI:    ca.aki,
		Body:   string(goodResp),
		Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	postRevoke := func() {
		ts := httptest.NewServer(NewOCSPHandler(dbAccessor, ca.signer))
		defer ts.Close()
		blob, _ := json.Marshal(map[string]string{
			"serial":             ca.serial,
			"authority_key_id":   ca.aki,
			"reason":             "keycompromise",
		})
		resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(blob))
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatal("revocation request failed: ", string(body))
		}
	}

	postRevoke()

	certs, _ := dbAccessor.GetCertificate(ca.serial, ca.aki)
	if len(certs) != 1 || certs[0].Status != "revoked" || certs[0].Reason != stdocsp.KeyCompromise {
		t.Fatalf("certificate not revoked correctly: %+v", certs)
	}
	firstRevokedAt := certs[0].RevokedAt

	rows, err := dbAccessor.GetOCSP(ca.serial, ca.aki)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected exactly one OCSP row, got %d", len(rows))
	}
	parsed, err := stdocsp.ParseResponse([]byte(rows[0].Body), nil)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Status != stdocsp.Revoked || parsed.RevocationReason != stdocsp.KeyCompromise {
		t.Fatalf("published OCSP should be revoked/keyCompromise, got %+v", parsed)
	}
	firstBody := rows[0].Body

	// A second revocation (retry) must stay idempotent: same reason,
	// same revocation time, same single OCSP response body.
	postRevoke()
	certs, _ = dbAccessor.GetCertificate(ca.serial, ca.aki)
	if !certs[0].RevokedAt.Equal(firstRevokedAt) || certs[0].Reason != stdocsp.KeyCompromise {
		t.Fatalf("retry changed revocation metadata: %+v", certs[0])
	}
	rows, _ = dbAccessor.GetOCSP(ca.serial, ca.aki)
	if len(rows) != 1 || rows[0].Body != firstBody {
		t.Fatal("retry must keep the single published OCSP response stable")
	}
}

// TestPendingGenerationRecovery simulates a process exit after the
// journal and signed OCSP candidate are durable but before the visible
// switch committed: cert is still good and no OCSP row exists. A later
// request resumes only the unconfirmed switch, regardless of which
// serial the new request targets.
func TestPendingGenerationRecovery(t *testing.T) {
	ca := newRevokeTestCA(t)
	dbAccessor, err := prepDB()
	if err != nil {
		t.Fatal(err)
	}
	insertLeaf(t, dbAccessor, ca, "good")

	manager := dbAccessor.(certdb.RevocationManager)
	rec, err := manager.BeginRevocation(ca.serial, ca.aki, stdocsp.KeyCompromise)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := ca.signer.Sign(ocsp.SignRequest{
		Certificate: ca.leaf,
		Status:      "revoked",
		Reason:      rec.Reason,
		RevokedAt:   rec.RevokedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsedCandidate, err := stdocsp.ParseResponse(candidate, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.SetRevocationOCSP(ca.serial, ca.aki,
		string(candidate), parsedCandidate.NextUpdate); err != nil {
		t.Fatal(err)
	}

	// Pre-switch state is still the previous consistent state.
	certs, _ := dbAccessor.GetCertificate(ca.serial, ca.aki)
	if certs[0].Status != "good" {
		t.Fatal("candidate preparation must not change the certificate")
	}
	if rows, _ := dbAccessor.GetOCSP(ca.serial, ca.aki); len(rows) != 0 {
		t.Fatal("candidate must not be visible before commit")
	}
	pending, err := manager.PendingRevocations()
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected one pending generation, got %+v %v", pending, err)
	}

	// Any subsequent revoke request sweeps and resumes the pending
	// generation (here: a different serial entirely).
	if resp, _ := testRevokeCert(t, dbAccessor, "1", fakeAKI, ""); resp.StatusCode != http.StatusOK {
		t.Fatal("recovery request should succeed")
	}

	certs, _ = dbAccessor.GetCertificate(ca.serial, ca.aki)
	if len(certs) != 1 || certs[0].Status != "revoked" || certs[0].Reason != stdocsp.KeyCompromise {
		t.Fatalf("recovered generation did not revoke certificate: %+v", certs)
	}
	rows, _ := dbAccessor.GetOCSP(ca.serial, ca.aki)
	if len(rows) != 1 || rows[0].Body != string(candidate) {
		t.Fatalf("recovered generation did not publish its candidate: %d rows", len(rows))
	}
	if parsed, err := stdocsp.ParseResponse([]byte(rows[0].Body), nil); err != nil ||
		parsed.Status != stdocsp.Revoked {
		t.Fatalf("recovered OCSP response invalid: %v %v", parsed, err)
	}
	if pending, _ := manager.PendingRevocations(); len(pending) != 0 {
		t.Fatalf("no generation should remain pending: %+v", pending)
	}

	// CRL input now includes the recovered serial.
	revokedCerts, err := dbAccessor.GetRevokedAndUnexpiredCertificates()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range revokedCerts {
		if c.Serial == ca.serial && c.AKI == ca.aki {
			found = true
		}
	}
	if !found {
		t.Fatal("recovered serial missing from CRL input")
	}
}

// legacyAccessor is a certdb.Accessor that intentionally does not
// implement RevocationManager, used to verify backwards compatibility.
type legacyAccessor struct {
	revoked  bool
	revCalls int
}

func (a *legacyAccessor) InsertCertificate(certdb.CertificateRecord) error { return nil }
func (a *legacyAccessor) GetCertificate(serial, aki string) ([]certdb.CertificateRecord, error) {
	return []certdb.CertificateRecord{{Serial: serial, AKI: aki, Status: "good"}}, nil
}
func (a *legacyAccessor) GetUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	return nil, nil
}
func (a *legacyAccessor) GetRevokedAndUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	return nil, nil
}
func (a *legacyAccessor) GetUnexpiredCertificatesByLabel([]string) ([]certdb.CertificateRecord, error) {
	return nil, nil
}
func (a *legacyAccessor) GetRevokedAndUnexpiredCertificatesByLabel(string) ([]certdb.CertificateRecord, error) {
	return nil, nil
}
func (a *legacyAccessor) GetRevokedAndUnexpiredCertificatesByLabelSelectColumns(string) ([]certdb.CertificateRecord, error) {
	return nil, nil
}
func (a *legacyAccessor) RevokeCertificate(serial, aki string, reasonCode int) error {
	a.revCalls++
	a.revoked = true
	return nil
}
func (a *legacyAccessor) InsertOCSP(certdb.OCSPRecord) error { return nil }
func (a *legacyAccessor) GetOCSP(serial, aki string) ([]certdb.OCSPRecord, error) {
	return nil, nil
}
func (a *legacyAccessor) GetUnexpiredOCSPs() ([]certdb.OCSPRecord, error) { return nil, nil }
func (a *legacyAccessor) UpdateOCSP(string, string, string, time.Time) error {
	return nil
}
func (a *legacyAccessor) UpsertOCSP(string, string, string, time.Time) error {
	return nil
}

// TestLegacyAccessorFallback verifies accessors without the
// RevocationManager extension keep the original handler behaviour.
func TestLegacyAccessorFallback(t *testing.T) {
	var _ certdb.Accessor = &legacyAccessor{}

	acc := &legacyAccessor{}
	ts := httptest.NewServer(NewHandler(acc))
	defer ts.Close()

	blob, _ := json.Marshal(map[string]string{"serial": "1", "authority_key_id": fakeAKI})
	resp, err := http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal("legacy path should succeed")
	}
	if acc.revCalls != 1 || !acc.revoked {
		t.Fatalf("legacy path should call RevokeCertificate once, got %d", acc.revCalls)
	}
}
