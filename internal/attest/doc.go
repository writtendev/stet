// Package attest verifies WebAuthn/CTAP2 "packed" attestation statements and
// classifies the key class of the authenticator that produced them.
//
// The package is unknown-by-default: any input that is malformed, uses an
// attestation format other than "packed", fails a certificate-chain check,
// is self-attested, or otherwise fails any single check in the verification
// algorithm classifies as ClassUnknown with Result.Verified set to false.
// There is exactly one path through Verify that returns a hardware class,
// and it is only reached after every check in the algorithm has passed.
// Self-attested and otherwise-unverified credentials are never rounded up
// to a hardware class, even if their signature is cryptographically valid.
//
// Verify never performs network access and never accepts caller-supplied
// trust roots: it verifies exclusively against a versioned set of vendor
// root CAs and an AAGUID capability table embedded in the binary at build
// time (see roots/manifest.json and metadata/aaguids.json for provenance).
package attest
