// Package ocsprefresh implements the ocsprefresh command.
package ocsprefresh

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/certdb/dbconf"
	"github.com/cloudflare/cfssl/certdb/sql"
	"github.com/cloudflare/cfssl/cli"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/ocsp"
	cryptoocsp "golang.org/x/crypto/ocsp"
)

// Usage text of 'cfssl ocsprefresh'
var ocsprefreshUsageText = `cfssl ocsprefresh -- refreshes the ocsp_responses table
with new OCSP responses for all known unexpired certificates

Usage of ocsprefresh:
        cfssl ocsprefresh -db-config db-config -ca cert -responder cert -responder-key key [-interval 96h]

Flags:
`

// Flags of 'cfssl ocsprefresh'
var ocsprefreshFlags = []string{"ca", "responder", "responder-key", "db-config", "interval"}

// confirmBatchSize bounds the number of candidates promoted in a single
// database transaction, keeping each commit recoverable.
const confirmBatchSize = 100

// ocsprefreshMain is the main CLI of OCSP refresh functionality.
func ocsprefreshMain(args []string, c cli.Config) error {
	if c.DBConfigFile == "" {
		return errors.New("need DB config file (provide with -db-config)")
	}

	if c.ResponderFile == "" {
		return errors.New("need responder certificate (provide with -responder)")
	}

	if c.ResponderKeyFile == "" {
		return errors.New("need responder key (provide with -responder-key)")
	}

	if c.CAFile == "" {
		return errors.New("need CA certificate (provide with -ca)")
	}

	s, err := SignerFromConfig(c)
	if err != nil {
		log.Critical("Unable to create OCSP signer: ", err)
		return err
	}

	// The responder certificate is used to validate each candidate
	// response signature before it is committed.
	responderPEM, err := helpers.ReadBytes(c.ResponderFile)
	if err != nil {
		return err
	}
	responder, err := helpers.ParseCertificatePEM(responderPEM)
	if err != nil {
		return err
	}

	db, err := dbconf.DBFromConfig(c.DBConfigFile)
	if err != nil {
		return err
	}

	return Refresh(sql.NewAccessor(db), s, responder, time.Duration(c.Interval))
}

// pendingKey identifies an OCSP record by its serial/AKI pair.
func pendingKey(serial, aki string) string {
	return serial + "\x00" + aki
}

// Refresh performs one recoverable OCSP refresh.
//
// It runs in two phases:
//
// Phase 1 reserves a pending slot for each selected unexpired certificate,
// generates a candidate OCSP response, validates it (well-formed, signed by
// the configured responder, matching serial), and stores the candidate in
// the slot. Certificates whose candidate fails to generate or validate keep
// their existing response and remain pending for the next run.
//
// Phase 2 confirms the candidates in bounded transactions. Each candidate
// replaces the stored response only when it is newer (strictly greater
// generation time), so a delayed or repeated refresh can never roll back a
// response produced by a more recent run. Confirmed slots are removed; an
// interrupted batch leaves the remaining candidates pending, and the next
// invocation only continues those unconfirmed certificates.
func Refresh(dbAccessor certdb.Accessor, signer ocsp.Signer, responder *x509.Certificate, interval time.Duration) error {
	certs, err := dbAccessor.GetUnexpiredCertificates()
	if err != nil {
		return err
	}

	pendingRecords, err := dbAccessor.GetPendingOCSPs()
	if err != nil {
		return err
	}
	pending := make(map[string]certdb.OCSPRecord, len(pendingRecords))
	for _, p := range pendingRecords {
		pending[pendingKey(p.Serial, p.AKI)] = p
	}

	var candidates []certdb.OCSPRecord
	var failedCount int
	now := time.Now()
	selected := make(map[string]bool, len(certs))

	for _, certRecord := range certs {
		key := pendingKey(certRecord.Serial, certRecord.AKI)
		selected[key] = true

		if existing, ok := pending[key]; ok {
			// Resume an interrupted refresh: reuse a candidate that was
			// already generated and validated, otherwise regenerate it.
			if existing.Body != "" && existing.Expiry.After(now) {
				candidates = append(candidates, existing)
				continue
			}
		} else {
			// Reserve the slot before signing. If the process exits at
			// any later point, the leftover slot marks this certificate
			// as unconfirmed.
			if err = dbAccessor.InsertPendingOCSP(certdb.OCSPRecord{
				Serial: certRecord.Serial,
				AKI:    certRecord.AKI,
			}); err != nil {
				return err
			}
		}

		candidate, err := generateCandidate(dbAccessor, signer, responder, certRecord, interval)
		if err != nil {
			// The existing response remains in ocsp_responses; the empty
			// pending slot causes the next run to retry this certificate.
			log.Errorf("Unable to refresh OCSP response for serial %s: %s", certRecord.Serial, err)
			failedCount++
			continue
		}

		candidates = append(candidates, candidate)
	}

	// Pending slots for certificates that are no longer selected (expired
	// or removed) are stale and must not be confirmed.
	for key, p := range pending {
		if !selected[key] {
			if err = dbAccessor.DeletePendingOCSP(p.Serial, p.AKI); err != nil {
				return err
			}
		}
	}

	// Phase 2: confirm candidates in recoverable batches.
	for start := 0; start < len(candidates); start += confirmBatchSize {
		end := start + confirmBatchSize
		if end > len(candidates) {
			end = len(candidates)
		}
		if err = dbAccessor.ConfirmOCSPs(candidates[start:end]); err != nil {
			return err
		}
	}

	if failedCount > 0 {
		return fmt.Errorf("OCSP refresh completed with %d unconfirmed certificate(s); they will be retried on the next run", failedCount)
	}
	return nil
}

// generateCandidate signs and validates one OCSP response, then stores it
// in the certificate's pending slot. The committed ocsp_responses table is
// never touched here.
func generateCandidate(dbAccessor certdb.Accessor, signer ocsp.Signer, responder *x509.Certificate, certRecord certdb.CertificateRecord, interval time.Duration) (certdb.OCSPRecord, error) {
	cert, err := helpers.ParseCertificatePEM([]byte(certRecord.PEM))
	if err != nil {
		return certdb.OCSPRecord{}, fmt.Errorf("unable to parse certificate: %s", err)
	}

	req := ocsp.SignRequest{
		Certificate: cert,
		Status:      certRecord.Status,
	}

	if certRecord.Status == "revoked" {
		req.Reason = int(certRecord.Reason)
		req.RevokedAt = certRecord.RevokedAt
	}

	rawResp, err := signer.Sign(req)
	if err != nil {
		return certdb.OCSPRecord{}, fmt.Errorf("unable to sign OCSP response: %s", err)
	}

	if err = validateCandidate(rawResp, cert, responder); err != nil {
		return certdb.OCSPRecord{}, fmt.Errorf("candidate OCSP response failed validation: %s", err)
	}

	generatedAt := time.Now()
	candidate := certdb.OCSPRecord{
		Serial:      cert.SerialNumber.String(),
		AKI:         hex.EncodeToString(cert.AuthorityKeyId),
		Body:        string(rawResp),
		Expiry:      generatedAt.Add(interval),
		GeneratedAt: generatedAt,
	}

	if err = dbAccessor.UpdatePendingOCSP(candidate); err != nil {
		return certdb.OCSPRecord{}, err
	}
	return candidate, nil
}

// validateCandidate checks a freshly generated response before it can
// replace the response currently in use:
//
//   - it must parse as a well-formed OCSP response;
//   - if it embeds a delegated responder certificate, that certificate
//     must be the responder configured for this refresh;
//   - its signature must verify against the responder's public key (this
//     covers responder==issuer deployments as well);
//   - its serial number must match the certificate being refreshed.
func validateCandidate(rawResp []byte, cert *x509.Certificate, responder *x509.Certificate) error {
	parsed, err := cryptoocsp.ParseResponse(rawResp, nil)
	if err != nil {
		return err
	}

	signerCert := responder
	if parsed.Certificate != nil {
		if !bytes.Equal(parsed.Certificate.Raw, responder.Raw) {
			return errors.New("response embeds a responder certificate different from the configured one")
		}
		signerCert = parsed.Certificate
	}

	if err = signerCert.CheckSignature(parsed.SignatureAlgorithm, parsed.TBSResponseData, parsed.Signature); err != nil {
		return fmt.Errorf("bad OCSP signature: %s", err)
	}

	if parsed.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		return errors.New("response serial does not match the certificate")
	}

	return nil
}

// SignerFromConfig creates a signer from a cli.Config as a helper for cli and serve
func SignerFromConfig(c cli.Config) (ocsp.Signer, error) {
	//if this is called from serve then we need to use the specific responder key file
	//fallback to key for backwards-compatibility
	k := c.ResponderKeyFile
	if k == "" {
		k = c.KeyFile
	}
	return ocsp.NewSignerFromFile(c.CAFile, c.ResponderFile, k, time.Duration(c.Interval))
}

// Command assembles the definition of Command 'ocsprefresh'
var Command = &cli.Command{UsageText: ocsprefreshUsageText, Flags: ocsprefreshFlags, Main: ocsprefreshMain}
