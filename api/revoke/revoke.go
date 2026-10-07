// Package revoke implements the HTTP handler for the revoke command
package revoke

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cloudflare/cfssl/api"
	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/ocsp"

	stdocsp "golang.org/x/crypto/ocsp"
)

// A Handler accepts requests with a serial number parameter
// and revokes
type Handler struct {
	dbAccessor certdb.Accessor
	Signer     ocsp.Signer
}

// NewHandler returns a new http.Handler that handles a revoke request.
func NewHandler(dbAccessor certdb.Accessor) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: dbAccessor,
		},
		Methods: []string{"POST"},
	}
}

// NewOCSPHandler returns a new http.Handler that handles a revoke
// request and also generates an OCSP response
func NewOCSPHandler(dbAccessor certdb.Accessor, signer ocsp.Signer) http.Handler {
	return &api.HTTPHandler{
		Handler: &Handler{
			dbAccessor: dbAccessor,
			Signer:     signer,
		},
		Methods: []string{"POST"},
	}
}

// This type is meant to be unmarshalled from JSON
type jsonRevokeRequest struct {
	Serial string `json:"serial"`
	AKI    string `json:"authority_key_id"`
	Reason string `json:"reason"`
}

// Handle responds to revocation requests. It attempts to revoke
// a certificate with a given serial number.
//
// When the backing accessor implements certdb.RevocationManager the
// revocation is committed as one resumable generation: serial/AKI and
// current status are validated first, then the certificate record (and
// CRL input), the immutable revocation reason/time and the OCSP
// candidate switch together. Any failure or process exit before the
// switch leaves the previous consistent state in place, and pending
// generations are resumed here instead of being started over, so repeat
// requests are idempotent and can never overwrite the committed
// revocation time/reason or restore a revoked certificate.
func (h *Handler) Handle(w http.ResponseWriter, r *http.Request) error {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return err
	}
	r.Body.Close()

	// Default the status to good so it matches the cli
	var req jsonRevokeRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return errors.NewBadRequestString("Unable to parse revocation request")
	}

	if len(req.Serial) == 0 {
		return errors.NewBadRequestString("serial number is required but not provided")
	}

	var reasonCode int
	reasonCode, err = ocsp.ReasonStringToCode(req.Reason)
	if err != nil {
		return errors.NewBadRequestString("Invalid reason code")
	}

	manager, managed := h.dbAccessor.(certdb.RevocationManager)
	if !managed {
		return h.handleLegacy(req, reasonCode, w)
	}

	// Recover generations left unconfirmed by a failed request or a
	// process exit: only the pending switch is repeated, nothing is
	// restarted. Best effort; a failure here must not block new
	// revocations.
	if err = h.recoverPending(manager); err != nil {
		return err
	}

	// Validate serial/AKI before recording any intent.
	crs, err := h.dbAccessor.GetCertificate(req.Serial, req.AKI)
	if err != nil {
		return err
	}
	if len(crs) == 0 {
		return errors.Wrap(errors.CertStoreError, errors.RecordNotFound,
			stderrors.New("failed to revoke the certificate: certificate not found"))
	}
	if len(crs) != 1 {
		return errors.NewBadRequestString("No unique certificate found")
	}

	// Begin the generation (or adopt the existing one: repeat
	// revocations are idempotent and keep the first reason/time).
	rec, err := manager.BeginRevocation(req.Serial, req.AKI, reasonCode)
	if err != nil {
		return err
	}

	// Prepare the OCSP candidate before anything becomes visible. The
	// candidate is derived from the immutable journal, so retries and
	// stale tasks sign the same reason/revocation time; the stored
	// candidate is first-writer-wins.
	if h.Signer != nil && rec.OCSPBody == "" {
		cert, perr := helpers.ParseCertificatePEM([]byte(crs[0].PEM))
		if perr != nil {
			return errors.NewBadRequestString("Unable to parse certificates from PEM data")
		}

		sr := ocsp.SignRequest{
			Certificate: cert,
			Status:      "revoked",
			Reason:      rec.Reason,
			RevokedAt:   rec.RevokedAt,
		}
		var ocspResponse []byte
		ocspResponse, err = h.Signer.Sign(sr)
		if err != nil {
			return err
		}

		var ocspParsed *stdocsp.Response
		ocspParsed, err = stdocsp.ParseResponse(ocspResponse, nil)
		if err != nil {
			return err
		}

		if err = manager.SetRevocationOCSP(req.Serial, req.AKI,
			string(ocspResponse), ocspParsed.NextUpdate); err != nil {
			return err
		}
	}

	// Atomic switch: certificate record/CRL input plus the OCSP
	// candidate become visible together, or not at all.
	if err = manager.CommitRevocation(req.Serial, req.AKI); err != nil {
		return err
	}

	result := map[string]string{}
	return api.SendResponse(w, result)
}

// recoverPending resumes generations with unconfirmed steps. Pending
// generations either carry their signed OCSP candidate already or were
// created without one, so the switch needs no signer here.
func (h *Handler) recoverPending(manager certdb.RevocationManager) error {
	pending, err := manager.PendingRevocations()
	if err != nil {
		return err
	}
	for _, rec := range pending {
		if err := manager.CommitRevocation(rec.Serial, rec.AKI); err != nil {
			return fmt.Errorf("resuming revocation for serial %s AKI %s: %w", rec.Serial, rec.AKI, err)
		}
	}
	return nil
}

// handleLegacy preserves the original revoke behaviour for accessors
// that do not implement the resumable RevocationManager extension.
func (h *Handler) handleLegacy(req jsonRevokeRequest, reasonCode int, w http.ResponseWriter) error {
	err := h.dbAccessor.RevokeCertificate(req.Serial, req.AKI, reasonCode)
	if err != nil {
		return err
	}

	// If we were given a signer, try and generate an OCSP
	// response indicating revocation
	if h.Signer != nil {
		// TODO: should these errors be errors?
		// Grab the certificate from the database
		cr, err := h.dbAccessor.GetCertificate(req.Serial, req.AKI)
		if err != nil {
			return err
		}
		if len(cr) != 1 {
			return errors.NewBadRequestString("No unique certificate found")
		}

		cert, err := helpers.ParseCertificatePEM([]byte(cr[0].PEM))
		if err != nil {
			return errors.NewBadRequestString("Unable to parse certificates from PEM data")
		}

		sr := ocsp.SignRequest{
			Certificate: cert,
			Status:      "revoked",
			Reason:      reasonCode,
			RevokedAt:   time.Now().UTC(),
		}

		ocspResponse, err := h.Signer.Sign(sr)
		if err != nil {
			return err
		}

		// We parse the OCSP response in order to get the next
		// update time/expiry time
		ocspParsed, err := stdocsp.ParseResponse(ocspResponse, nil)
		if err != nil {
			return err
		}

		ocspRecord := certdb.OCSPRecord{
			Serial: req.Serial,
			AKI:    req.AKI,
			Body:   string(ocspResponse),
			Expiry: ocspParsed.NextUpdate,
		}

		if err = h.dbAccessor.InsertOCSP(ocspRecord); err != nil {
			return err
		}
	}

	result := map[string]string{}
	return api.SendResponse(w, result)
}
