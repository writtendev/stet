//go:build cgo && libfido2

// Package fido: this file is the cgo backend, built only with the libfido2
// build tag (and cgo enabled). It talks to libfido2 1.14's API surface only
// — see the package-level notes on unwrapCBORByteString for why the newer
// *_raw_ptr accessors are avoided.
package fido

/*
#cgo pkg-config: libfido2
#include <fido.h>
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"sync"
	"time"
	"unsafe"
)

// Backend names the compiled-in authenticator backend.
const Backend = "libfido2"

var fidoInitOnce sync.Once

// New returns an Authenticator backed by libfido2.
func New() Authenticator {
	fidoInitOnce.Do(func() {
		C.fido_init(0)
	})
	return libfido2Authenticator{}
}

type libfido2Authenticator struct{}

// Devices enumerates connected authenticators via
// fido_dev_info_new/manifest/ptr and the per-device accessors.
func (libfido2Authenticator) Devices(_ context.Context) ([]DeviceInfo, error) {
	const maxDevices = 64

	list := C.fido_dev_info_new(C.size_t(maxDevices))
	if list == nil {
		return nil, fmt.Errorf("fido2: fido_dev_info_new failed")
	}
	defer C.fido_dev_info_free(&list, C.size_t(maxDevices))

	var found C.size_t
	if rc := C.fido_dev_info_manifest(list, C.size_t(maxDevices), &found); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	devices := make([]DeviceInfo, 0, int(found))
	for i := C.size_t(0); i < found; i++ {
		di := C.fido_dev_info_ptr(list, i)
		if di == nil {
			continue
		}
		devices = append(devices, DeviceInfo{
			Path:         C.GoString(C.fido_dev_info_path(di)),
			Manufacturer: C.GoString(C.fido_dev_info_manufacturer_string(di)),
			Product:      C.GoString(C.fido_dev_info_product_string(di)),
			VendorID:     int16(C.fido_dev_info_vendor(di)),
			ProductID:    int16(C.fido_dev_info_product(di)),
		})
	}
	return devices, nil
}

// MakeCredential performs a CTAP2 make-credential ceremony. It never
// requests a resident/discoverable credential and only requests user
// verification when req.RequireUV is set.
func (libfido2Authenticator) MakeCredential(ctx context.Context, devicePath string, req CredentialRequest) (*Credential, error) {
	if req.RequireUV && req.PIN == "" {
		return nil, ErrPINRequired
	}
	alg := req.Algorithm
	if alg == 0 {
		alg = ES256
	}
	rpID := req.RPID
	if rpID == "" {
		rpID = DefaultRPID
	}

	dev, err := openDevice(devicePath)
	if err != nil {
		return nil, err
	}
	defer closeDevice(dev)

	cred := C.fido_cred_new()
	if cred == nil {
		return nil, fmt.Errorf("fido2: fido_cred_new failed")
	}
	defer C.fido_cred_free(&cred)

	if rc := C.fido_cred_set_type(cred, C.int(alg)); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	clientDataHash := req.ClientDataHash
	if rc := C.fido_cred_set_clientdata_hash(cred, bytesPtr(clientDataHash[:]), C.size_t(len(clientDataHash))); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	cRPID := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRPID))
	var cRPName *C.char
	if req.RPName != "" {
		cRPName = C.CString(req.RPName)
		defer C.free(unsafe.Pointer(cRPName))
	}
	if rc := C.fido_cred_set_rp(cred, cRPID, cRPName); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	cUserName := C.CString(req.UserName)
	defer C.free(unsafe.Pointer(cUserName))
	if rc := C.fido_cred_set_user(cred, bytesPtr(req.UserID), C.size_t(len(req.UserID)), cUserName, nil, nil); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	if rc := C.fido_cred_set_rk(cred, C.FIDO_OPT_FALSE); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}
	if req.RequireUV {
		if rc := C.fido_cred_set_uv(cred, C.FIDO_OPT_TRUE); rc != C.FIDO_OK {
			return nil, mapErr(int(rc))
		}
	}

	var cPIN *C.char
	if req.PIN != "" {
		cPIN = C.CString(req.PIN)
		defer zeroAndFreeCString(cPIN, len(req.PIN))
	}

	if err := runCancelable(ctx, dev, func() C.int {
		return C.fido_dev_make_cred(dev, cred, cPIN)
	}); err != nil {
		return nil, err
	}

	wrappedAuthData := goBytes(C.fido_cred_authdata_ptr(cred), C.fido_cred_authdata_len(cred))
	authData, err := unwrapCBORByteString(wrappedAuthData)
	if err != nil {
		return nil, fmt.Errorf("fido2: unwrap credential authData: %w", err)
	}

	rawPubKey := goBytes(C.fido_cred_pubkey_ptr(cred), C.fido_cred_pubkey_len(cred))
	pkixPubKey, err := publicKeyToPKIX(alg, rawPubKey)
	if err != nil {
		return nil, err
	}

	out := &Credential{
		Format:         C.GoString(C.fido_cred_fmt(cred)),
		AuthData:       authData,
		AttStmt:        goBytes(C.fido_cred_attstmt_ptr(cred), C.fido_cred_attstmt_len(cred)),
		ClientDataHash: req.ClientDataHash,
		CredentialID:   goBytes(C.fido_cred_id_ptr(cred), C.fido_cred_id_len(cred)),
		Algorithm:      alg,
		PublicKey:      pkixPubKey,
		Flags:          flagsFromByte(C.fido_cred_flags(cred)),
	}
	copy(out.AAGUID[:], goBytes(C.fido_cred_aaguid_ptr(cred), C.fido_cred_aaguid_len(cred)))

	return out, nil
}

// GetAssertion performs a CTAP2 get-assertion ceremony. User presence is
// always requested; user verification is requested only when
// req.RequireUV is set. Discoverable credentials are not supported: the
// allow list (req.CredentialIDs) is required.
func (libfido2Authenticator) GetAssertion(ctx context.Context, devicePath string, req AssertionRequest) (*Assertion, error) {
	if req.RequireUV && req.PIN == "" {
		return nil, ErrPINRequired
	}
	if len(req.CredentialIDs) == 0 {
		return nil, fmt.Errorf("fido2: GetAssertion requires at least one allowed credential ID")
	}
	rpID := req.RPID
	if rpID == "" {
		rpID = DefaultRPID
	}

	dev, err := openDevice(devicePath)
	if err != nil {
		return nil, err
	}
	defer closeDevice(dev)

	assert := C.fido_assert_new()
	if assert == nil {
		return nil, fmt.Errorf("fido2: fido_assert_new failed")
	}
	defer C.fido_assert_free(&assert)

	clientDataHash := req.ClientDataHash
	if rc := C.fido_assert_set_clientdata_hash(assert, bytesPtr(clientDataHash[:]), C.size_t(len(clientDataHash))); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	cRPID := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRPID))
	if rc := C.fido_assert_set_rp(assert, cRPID); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}

	for _, id := range req.CredentialIDs {
		if rc := C.fido_assert_allow_cred(assert, bytesPtr(id), C.size_t(len(id))); rc != C.FIDO_OK {
			return nil, mapErr(int(rc))
		}
	}

	if rc := C.fido_assert_set_up(assert, C.FIDO_OPT_TRUE); rc != C.FIDO_OK {
		return nil, mapErr(int(rc))
	}
	if req.RequireUV {
		if rc := C.fido_assert_set_uv(assert, C.FIDO_OPT_TRUE); rc != C.FIDO_OK {
			return nil, mapErr(int(rc))
		}
	}

	var cPIN *C.char
	if req.PIN != "" {
		cPIN = C.CString(req.PIN)
		defer zeroAndFreeCString(cPIN, len(req.PIN))
	}

	if err := runCancelable(ctx, dev, func() C.int {
		return C.fido_dev_get_assert(dev, assert, cPIN)
	}); err != nil {
		return nil, err
	}

	var idx C.size_t // libfido2 returns exactly one assertion for an allow-list request; read index 0.

	wrappedAuthData := goBytes(C.fido_assert_authdata_ptr(assert, idx), C.fido_assert_authdata_len(assert, idx))
	authData, err := unwrapCBORByteString(wrappedAuthData)
	if err != nil {
		return nil, fmt.Errorf("fido2: unwrap assertion authData: %w", err)
	}

	return &Assertion{
		AuthData:       authData,
		Signature:      goBytes(C.fido_assert_sig_ptr(assert, idx), C.fido_assert_sig_len(assert, idx)),
		CredentialID:   goBytes(C.fido_assert_id_ptr(assert, idx), C.fido_assert_id_len(assert, idx)),
		ClientDataHash: req.ClientDataHash,
		SignCount:      uint32(C.fido_assert_sigcount(assert, idx)),
		Flags:          flagsFromByte(C.fido_assert_flags(assert, idx)),
	}, nil
}

// openDevice opens the device at path and rejects it with ErrNotFIDO2 if it
// does not speak CTAP2. stet never calls fido_dev_force_u2f: there is no
// U2F fallback.
func openDevice(path string) (*C.fido_dev_t, error) {
	dev := C.fido_dev_new()
	if dev == nil {
		return nil, fmt.Errorf("fido2: fido_dev_new failed")
	}

	cPath := C.CString(path)
	defer C.free(unsafe.Pointer(cPath))

	if rc := C.fido_dev_open(dev, cPath); rc != C.FIDO_OK {
		C.fido_dev_free(&dev)
		// A failure to open the transport at all — wrong path, device
		// unplugged, permission denied — is always "no device", by
		// ErrNoDevice's own definition, regardless of libfido2's more
		// granular (and platform-dependent) FIDO_ERR_* code.
		return nil, ErrNoDevice
	}
	if !bool(C.fido_dev_is_fido2(dev)) {
		C.fido_dev_close(dev)
		C.fido_dev_free(&dev)
		return nil, ErrNotFIDO2
	}
	return dev, nil
}

func closeDevice(dev *C.fido_dev_t) {
	C.fido_dev_close(dev)
	C.fido_dev_free(&dev)
}

// cancelRetryInterval is how often runCancelable re-sends
// CTAPHID_CANCEL while waiting for a cancelled call to return.
// fido_dev_cancel is a fire-and-forget packet: if fn hasn't yet reached
// libfido2's blocking read (or the authenticator otherwise missed it), a
// single cancel is dropped silently. Retrying bounds how long a lost
// cancel can block the caller.
const cancelRetryInterval = 50 * time.Millisecond

// runCancelable runs a blocking libfido2 call (fido_dev_make_cred or
// fido_dev_get_assert) on its own goroutine, so that a cancelled ctx can
// call fido_dev_cancel and this returns promptly with ErrCancelled instead
// of blocking until the authenticator times out on its own.
//
// It never races a completed ceremony against the cancellation: once fn's
// result is available on done, that result is always what gets returned,
// even if ctx was also cancelled around the same time. If ctx is already
// done before fn is even started, fn is never invoked (and the device is
// never touched) and ErrCancelled is returned immediately.
func runCancelable(ctx context.Context, dev *C.fido_dev_t, fn func() C.int) error {
	if err := ctx.Err(); err != nil {
		return ErrCancelled
	}

	done := make(chan C.int, 1)
	go func() {
		done <- fn()
	}()

	select {
	case rc := <-done:
		return resultFromRC(rc)
	case <-ctx.Done():
	}

	// ctx was cancelled while fn was running (or before libfido2's request
	// actually reached the authenticator). Keep sending CTAPHID_CANCEL
	// until fn returns; whatever it returns wins, including a result that
	// snuck in and completed successfully despite the cancellation.
	ticker := time.NewTicker(cancelRetryInterval)
	defer ticker.Stop()
	C.fido_dev_cancel(dev)
	for {
		select {
		case rc := <-done:
			return resultFromRC(rc)
		case <-ticker.C:
			C.fido_dev_cancel(dev)
		}
	}
}

func resultFromRC(rc C.int) error {
	if rc != C.FIDO_OK {
		return mapErr(int(rc))
	}
	return nil
}

// flagsFromByte decodes a raw authenticator-data flags byte, as returned by
// fido_cred_flags / fido_assert_flags, into a Flags value.
func flagsFromByte(b C.uint8_t) Flags {
	f := uint8(b)
	return Flags{
		UserPresent:            f&flagUserPresent != 0,
		UserVerified:           f&flagUserVerified != 0,
		AttestedCredentialData: f&flagAttestedCredentialData != 0,
	}
}

// bytesPtr returns a pointer to b's backing array for passing into a
// libfido2 call, or nil for an empty slice (libfido2 treats a NULL/0-length
// buffer as absent).
func bytesPtr(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// goBytes copies a libfido2-owned buffer into Go-managed memory. Every
// buffer read from a *_cred_t/*_assert_t must be copied before the struct
// is freed.
func goBytes(ptr *C.uchar, length C.size_t) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}

// zeroAndFreeCString overwrites a C string's bytes before freeing it, so a
// PIN does not linger in memory longer than necessary.
func zeroAndFreeCString(s *C.char, length int) {
	buf := unsafe.Slice((*byte)(unsafe.Pointer(s)), length)
	for i := range buf {
		buf[i] = 0
	}
	C.free(unsafe.Pointer(s))
}

// mapErr maps a libfido2 FIDO_ERR_* code onto stet's sentinel errors.
func mapErr(rc int) error {
	switch rc {
	case C.FIDO_OK:
		return nil
	case C.FIDO_ERR_PIN_REQUIRED:
		return ErrPINRequired
	case C.FIDO_ERR_PIN_INVALID:
		return ErrPINInvalid
	case C.FIDO_ERR_ACTION_TIMEOUT:
		return ErrActionTimeout
	case C.FIDO_ERR_OPERATION_DENIED:
		return ErrOperationDenied
	case C.FIDO_ERR_NO_CREDENTIALS:
		return ErrNoCredentials
	case C.FIDO_ERR_UNSUPPORTED_ALGORITHM:
		return ErrUnsupportedAlgorithm
	case C.FIDO_ERR_KEEPALIVE_CANCEL:
		return ErrCancelled
	case C.FIDO_ERR_RX, C.FIDO_ERR_TX:
		return ErrNoDevice
	default:
		return fmt.Errorf("fido2: %s", C.GoString(C.fido_strerr(C.int(rc))))
	}
}
