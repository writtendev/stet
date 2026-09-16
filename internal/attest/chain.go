package attest

import (
	"bytes"
	"crypto/x509"
	"errors"
	"time"
)

// requiredLeafOU is the Subject Organizational Unit every packed
// attestation leaf certificate must carry (WebAuthn ยง8.2.1).
const requiredLeafOU = "Authenticator Attestation"

// leafSanityChecks implements algorithm step 5: structural and identity
// checks on x5c[0] that do not require building a chain. It returns a
// policy reason code, or "" if leaf passes every check.
func leafSanityChecks(leaf *x509.Certificate, trust *trustStore) string {
	// Checked first: a leaf that is self-signed, or byte-equal to one of
	// the bundled vendor roots, is self-attestation regardless of what its
	// own basic constraints say (a bundled root is itself a CA, but that
	// must not surface as reasonLeafIsCA instead of self-attestation).
	if isSelfSigned(leaf) || trust.isBundledRoot(leaf) {
		return reasonSelfAttestation
	}

	if leaf.Version != 3 {
		return reasonLeafNotV3
	}
	// Basic constraints must be present (not merely absent-and-defaulted)
	// and must say this is not a CA.
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return reasonLeafIsCA
	}

	subj := leaf.Subject
	if len(subj.Country) == 0 || len(subj.Organization) == 0 || subj.CommonName == "" {
		return reasonLeafSubjectIncomplete
	}
	if !hasExactOU(subj.OrganizationalUnit, requiredLeafOU) {
		return reasonLeafWrongOU
	}

	return ""
}

func hasExactOU(ous []string, want string) bool {
	for _, ou := range ous {
		if ou == want {
			return true
		}
	}
	return false
}

// isSelfSigned reports whether cert's issuer and subject match and cert's
// own signature verifies against its own embedded public key. This is a
// pure cryptographic check: unlike CheckSignatureFrom, it does not also
// require the certificate to satisfy CA basic-constraints semantics, since
// a self-attested (or root-equal) leaf is not necessarily marked as a CA.
func isSelfSigned(cert *x509.Certificate) bool {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// verifyChain implements algorithm step 8: it builds an intermediate pool
// from x5c[1:] (skipping any self-signed certificate found there, which is
// never a trust anchor in this package's model), then verifies leaf against
// the bundled trust store at opts.At. It returns the verified chain
// (leaf-to-root) or a policy reason code.
func verifyChain(leaf *x509.Certificate, x5c [][]byte, trust *trustStore, at time.Time) ([]*x509.Certificate, string) {
	intermediates := x509.NewCertPool()
	for _, der := range x5c[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, reasonChainUntrusted
		}
		if isSelfSigned(cert) {
			continue
		}
		intermediates.AddCert(cert)
	}

	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         trust.pool,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
			return nil, reasonChainExpired
		}
		return nil, reasonChainUntrusted
	}
	if len(chains) == 0 {
		return nil, reasonChainUntrusted
	}

	return chains[0], ""
}
