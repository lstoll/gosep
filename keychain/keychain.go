package keychain

/*
#cgo CFLAGS: -x objective-c -mmacosx-version-min=10.13
#cgo LDFLAGS: -framework Foundation -framework CoreFoundation -framework Security
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

#import "keychain.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

var (
	ErrMissingEntitlement = errors.New("application missing necessary entitlements for keychain access")
	ErrKeyNotFound        = errors.New("key not found")
)

func CreateKey() error {
	// var in = new(C.createKeyIn)
	// in.inmessage = C.CString("hello")
	var out *C.createKeyOut
	var cErr *C.error

	in := &C.createKeyIn{
		tag:        C.CString("li.lds.osxsecure.testkey1"),
		protection: C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
	}

	C.createKey(in, &out, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
		if cErr.code == C.errSecMissingEntitlement {
			return ErrMissingEntitlement
		}
		// TODO - handle -34018 more informatively (missing entitlement)
		return fmt.Errorf(C.GoString(cErr.message))
	}
	if out == nil {
		return fmt.Errorf("no return")
	}
	defer C.free(unsafe.Pointer(out))

	return nil
}

func GetKey() error {
	// var in = new(C.createKeyIn)
	// in.inmessage = C.CString("hello")
	var out *C.getKeyOut
	var cErr *C.error

	in := &C.getKeyIn{
		tag: C.CString("li.lds.osxsecure.testkey1"),
	}

	C.getKey(in, &out, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
		if cErr.code == C.errSecItemNotFound {
			return ErrKeyNotFound
		}
		return fmt.Errorf(C.GoString(cErr.message))
	}
	if out == nil {
		return fmt.Errorf("no return")
	}
	defer C.free(unsafe.Pointer(out))

	return nil
}

// type Key struct {
// 	pub  C.SecKeyRef
// 	priv C.SecKeyRef
// }

// func CreateKey() (*Key, error) {
// 	// https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/generating_new_cryptographic_keys?language=objc

// 	opts := map[C.CFTypeRef]C.CFTypeRef{
// 		C.CFTypeRef(C.kSecAttrKeyType):       C.CFTypeRef(C.kSecAttrKeyTypeRSA),
// 		C.CFTypeRef(C.kSecAttrKeySizeInBits): C.CFTypeRef(int64ToCFNumber(2048)),
// 	}

// 	var cfErr C.CFErrorRef
// 	pk := C.SecKeyCreateRandomKey(mapToCFDictionary(opts), &cfErr)

// 	if !nilCFErrorRef(cfErr) {
// 		// TODO - parse it?
// 		return nil, fmt.Errorf("failed")
// 	}

// 	return &Key{
// 		pub:  C.SecKeyCopyPublicKey(pk),
// 		priv: pk,
// 	}, nil
// }

// func (k *Key) Public() crypto.PublicKey {
// 	return nil
// }

// func (k *Key) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
// 	// https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/signing_and_verifying?language=objc#overview
// 	cfDigest, err := bytesToCFDataRef(digest)
// 	if err != nil {
// 		return nil, err
// 	}
// 	var cfErr C.CFErrorRef
// 	csig := C.SecKeyCreateSignature(k.priv, C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, cfDigest, &cfErr)
// 	if !nilCFErrorRef(cfErr) {
// 		return nil, fmt.Errorf("signing: %v", cfErrorRefToError(cfErr))
// 	}
// 	defer C.CFRelease(C.CFTypeRef(csig))
// 	return cfDataRefToBytes(csig), nil
// }

// func (k *Key) Close() {
// 	if !nilSecKeyRef(k.pub) {
// 		C.CFRelease(C.CFTypeRef(k.pub))
// 	}
// 	if !nilSecKeyRef(k.priv) {
// 		C.CFRelease(C.CFTypeRef(k.priv))
// 	}
// }

// func nilSecKeyRef(r C.SecKeyRef) bool {
// 	return r == 0
// }

// var _ crypto.Signer = (*Key)(nil)
