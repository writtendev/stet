package attest

import (
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// Class is an authenticator's classified key class. The zero value is
// ClassUnknown, so a zero-value Result is never mistaken for a verified
// hardware credential.
type Class int

const (
	ClassUnknown Class = iota
	ClassHardwareTouch
	ClassHardwarePIN
	ClassHardwareBiometric
)

var classNames = map[Class]string{
	ClassUnknown:           "unknown",
	ClassHardwareTouch:     "hardware+touch",
	ClassHardwarePIN:       "hardware+PIN",
	ClassHardwareBiometric: "hardware+biometric",
}

func (c Class) String() string {
	if s, ok := classNames[c]; ok {
		return s
	}
	return "unknown"
}

func (c Class) MarshalText() ([]byte, error) {
	return []byte(c.String()), nil
}

func (c *Class) UnmarshalText(text []byte) error {
	s := string(text)
	for k, v := range classNames {
		if v == s {
			*c = k
			return nil
		}
	}
	return fmt.Errorf("attest: unknown class %q", s)
}

// Stable machine-readable reason codes. See doc.go for the package's
// unknown-by-default contract: every one of these can appear in
// Result.Reasons with Class == ClassUnknown and err == nil.
const (
	reasonRPIDMismatch          = "rpid-mismatch"
	reasonUserNotPresent        = "user-not-present"
	reasonNoAttestation         = "no-attestation"
	reasonUnsupportedFormat     = "unsupported-format"
	reasonSelfAttestation       = "self-attestation"
	reasonUnsupportedECDAA      = "unsupported-ecdaa"
	reasonLeafNotV3             = "leaf-not-v3"
	reasonLeafIsCA              = "leaf-is-ca"
	reasonLeafSubjectIncomplete = "leaf-subject-incomplete"
	reasonLeafWrongOU           = "leaf-wrong-ou"
	reasonAlgKeyMismatch        = "alg-key-mismatch"
	reasonUnsupportedAlg        = "unsupported-alg"
	reasonBadSignature          = "bad-signature"
	reasonAAGUIDExtCritical     = "aaguid-ext-critical"
	reasonAAGUIDExtMalformed    = "aaguid-ext-malformed"
	reasonAAGUIDMismatch        = "aaguid-mismatch"
	reasonAAGUIDUnbound         = "aaguid-unbound"
	reasonAAGUIDZero            = "aaguid-zero"
	reasonChainUntrusted        = "chain-untrusted"
	reasonChainExpired          = "chain-expired"
	reasonAAGUIDNotInMetadata   = "aaguid-not-in-metadata"
	reasonAAGUIDVendorMismatch  = "aaguid-vendor-mismatch"
)

// Result is the outcome of Verify.
type Result struct {
	Class          Class    `json:"class"`
	Verified       bool     `json:"verified"`
	Format         string   `json:"format"`
	AAGUID         string   `json:"aaguid"`
	Vendor         string   `json:"vendor,omitempty"`
	Model          string   `json:"model,omitempty"`
	RootSHA256     string   `json:"root_sha256,omitempty"`
	UserPresent    bool     `json:"user_present"`
	UserVerified   bool     `json:"user_verified"`
	CredentialID   []byte   `json:"credential_id"`
	CredentialKey  []byte   `json:"credential_public_key"`
	Reasons        []string `json:"reasons,omitempty"`
	RootSetVersion int      `json:"root_set_version"`
}

// Options configures a Verify call.
type Options struct {
	// At is the instant chain validity is evaluated at (enrollment time).
	// It is required: a zero value is an error, so audits stay
	// deterministic instead of silently defaulting to time.Now.
	At time.Time
}

// Verify verifies a packed attestation statement against this package's
// embedded, versioned vendor trust material and classifies its key class.
// See doc.go for the unknown-by-default contract and the algorithm's
// verification order.
func Verify(st Statement, opts Options) (Result, error) {
	return verify(st, opts, embeddedTrust)
}

// verify is Verify's implementation, parameterized on the trust store so
// tests can inject a throwaway test-only CA (and a matching synthetic
// AAGUID table) without ever touching the embedded, versioned root set.
//
// Every return in this function either appends a reason code to res and
// returns res with Class left at its zero value (ClassUnknown), or returns
// a non-nil error for malformed input (res.Class is still ClassUnknown in
// that case too), except for the single success path at the end.
func verify(st Statement, opts Options, trust *trustStore) (Result, error) {
	var res Result
	res.Format = st.Format

	if opts.At.IsZero() {
		return res, errors.New("attest: Options.At must be set")
	}
	if len(st.ClientDataHash) != 32 {
		return res, fmt.Errorf("attest: ClientDataHash must be exactly 32 bytes, got %d", len(st.ClientDataHash))
	}

	// Step 1: authData parse.
	ad, err := parseAuthData(st.AuthData)
	if err != nil {
		return res, err
	}
	res.AAGUID = formatAAGUID(ad.AAGUID)
	res.UserPresent = ad.UserPresent
	res.UserVerified = ad.UserVerified
	res.CredentialID = ad.CredentialID
	res.CredentialKey = ad.COSEKey

	if !rpIDHashMatches(ad, st.RPID) {
		res.Reasons = append(res.Reasons, reasonRPIDMismatch)
		return res, nil
	}
	if !ad.UserPresent {
		res.Reasons = append(res.Reasons, reasonUserNotPresent)
		return res, nil
	}

	// Step 2: format dispatch. Only "packed" can reach a hardware class.
	switch st.Format {
	case "packed":
		// fall through to step 3.
	case "none":
		res.Reasons = append(res.Reasons, reasonNoAttestation)
		return res, nil
	default:
		res.Reasons = append(res.Reasons, reasonUnsupportedFormat)
		return res, nil
	}

	// Step 3: attStmt decode.
	stmt, err := decodePackedAttStmt(st.AttStmt)
	if err != nil {
		return res, err
	}

	// Step 4: self attestation / ECDAA. ECDAA is checked first because an
	// ECDAA statement's x5c is also absent, and it must not be reported as
	// plain self-attestation.
	if len(stmt.ECDAAKeyID) > 0 {
		res.Reasons = append(res.Reasons, reasonUnsupportedECDAA)
		return res, nil
	}
	if len(stmt.X5C) == 0 {
		res.Reasons = append(res.Reasons, reasonSelfAttestation)
		return res, nil
	}

	leaf, err := x509.ParseCertificate(stmt.X5C[0])
	if err != nil {
		return res, err
	}

	// Step 5: leaf cert checks.
	if reason := leafSanityChecks(leaf, trust); reason != "" {
		res.Reasons = append(res.Reasons, reason)
		return res, nil
	}

	// Step 6: signature.
	if reason := verifyPackedSignature(leaf, stmt.Alg, stmt.Sig, st.AuthData, st.ClientDataHash); reason != "" {
		res.Reasons = append(res.Reasons, reason)
		return res, nil
	}

	// Step 7: AAGUID extension.
	if reason := checkAAGUIDExtension(leaf, ad.AAGUID); reason != "" {
		res.Reasons = append(res.Reasons, reason)
		return res, nil
	}

	// Step 8: chain. leaf.Verify can return more than one valid chain (a
	// cross-signed intermediate, or two bundled roots sharing a subject),
	// so every chain is considered in step 9 rather than assuming index 0:
	// which chain the AAGUID table endorses must not depend on the order
	// an authenticator happened to put intermediates in x5c.
	chains, reason := verifyChain(leaf, stmt.X5C, trust, opts.At)
	if reason != "" {
		res.Reasons = append(res.Reasons, reason)
		return res, nil
	}

	// Step 9: vendor/AAGUID cross-check.
	rec, ok := trust.aaguids[ad.AAGUID]
	if !ok {
		res.Reasons = append(res.Reasons, reasonAAGUIDNotInMetadata)
		return res, nil
	}

	var rootSHA256, vendor string
	matched := false
	for _, chain := range chains {
		root := chain[len(chain)-1]
		sha256hex, v, ok := trust.lookupRoot(root)
		if !ok {
			// leaf.Verify only ever returns chains anchored in trust.pool,
			// so this should be unreachable; skip rather than trust it.
			continue
		}
		if rec.rootSHA256[sha256hex] {
			rootSHA256, vendor = sha256hex, v
			matched = true
			break
		}
	}
	if !matched {
		res.Reasons = append(res.Reasons, reasonAAGUIDVendorMismatch)
		return res, nil
	}

	// Step 10: classify. Every check has passed.
	res.Verified = true
	res.Vendor = vendor
	res.Model = rec.model
	res.RootSHA256 = rootSHA256
	res.RootSetVersion = trust.rootSetVersion
	res.Class = classifyClass(ad.UserVerified, rec.uvMethods)

	return res, nil
}

// classifyClass implements algorithm step 10's classification rule.
// Authenticators that support both a biometric and a PIN/passcode UV
// method (e.g. YubiKey Bio) classify as hardware+PIN, not
// hardware+biometric: at make-credential time this package cannot prove
// which UV method was actually used, so it does not claim biometric.
func classifyClass(userVerified bool, uvMethods map[string]bool) Class {
	if !userVerified {
		return ClassHardwareTouch
	}
	hasFingerprint := uvMethods["fingerprint_internal"]
	hasPasscode := uvMethods["passcode_external"] || uvMethods["passcode_internal"]
	if hasFingerprint && !hasPasscode {
		return ClassHardwareBiometric
	}
	return ClassHardwarePIN
}
