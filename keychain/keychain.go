package keychain

/*
#cgo CFLAGS: -x objective-c -mmacosx-version-min=10.13 -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework CoreFoundation -framework Security
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>
#import <stdlib.h>

#import "keychain.h"
*/
import "C"
import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"
)

var (
	ErrMissingEntitlement = errors.New("application missing necessary entitlements for keychain access")
	ErrKeyNotFound        = errors.New("key not found")
	ErrKeyAlreadyExists   = errors.New("key with given tag already exists")
)

type Key struct {
	priv C.SecKeyRef
	pub  *ecdsa.PublicKey
}

func (k *Key) Public() crypto.PublicKey {
	return k.pub
}

func CreateKey(tag string) (*Key, error) {
	k, err := GetKey(tag)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	if k != nil {
		return nil, ErrKeyAlreadyExists
	}

	// var in = new(C.createKeyIn)
	// in.inmessage = C.CString("hello")
	var out *C.createKeyOut
	var cErr *C.error

	in := &C.createKeyIn{
		tag:        C.CString("li.lds.gosep.testkey1"),
		protection: C.kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
	}

	C.createKey(in, &out, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
		if cErr.code == C.errSecMissingEntitlement {
			return nil, ErrMissingEntitlement
		}
		// TODO - handle -34018 more informatively (missing entitlement)
		return nil, fmt.Errorf(C.GoString(cErr.message))
	}
	if out == nil {
		return nil, fmt.Errorf("no return")
	}
	defer C.free(unsafe.Pointer(out))

	k = &Key{
		priv: out.privateKey,
	}
	runtime.SetFinalizer(k, freeKey)

	if err := k.setPublic(); err != nil {
		return nil, err
	}

	return k, nil
}

func GetKey(tag string) (*Key, error) {
	var (
		out  *C.getKeyOut
		cErr *C.error
	)

	in := &C.getKeyIn{
		tag: C.CString(tag),
	}

	C.getKey(in, &out, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
		if cErr.code == C.errSecItemNotFound {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf(C.GoString(cErr.message))
	}
	if out == nil {
		return nil, fmt.Errorf("no error, but not return")
	}
	defer C.free(unsafe.Pointer(out))

	k := &Key{
		priv: out.privateKey,
	}
	runtime.SetFinalizer(k, freeKey)

	if err := k.setPublic(); err != nil {
		return nil, err
	}

	return k, nil
}

func DeleteKey(tag string) error {
	var (
		cErr *C.error
	)

	in := &C.getKeyIn{
		tag: C.CString(tag),
	}

	C.deleteKey(in, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
		if cErr.code == C.errSecItemNotFound {
			return ErrKeyNotFound
		}
		return fmt.Errorf("deleting key: %v", C.GoString(cErr.message))
	}
	return nil
}

var freeKey = func(k *Key) {
	if k.priv != 0 {
		C.CFRelease(C.CFTypeRef(k.priv))
	}

}

func (k *Key) setPublic() error {
	var (
		size C.size_t
		buf  *C.char
		cErr *C.error
	)

	C.publicKey(k.priv, &size, &buf, &cErr)
	if cErr != nil {
		defer C.free(unsafe.Pointer(cErr))
		if cErr.code == C.errSecItemNotFound {
			return ErrKeyNotFound
		}
		return fmt.Errorf("populating public key: %v", C.GoString(cErr.message))
	}
	defer C.free(unsafe.Pointer(buf))

	pb := C.GoBytes(unsafe.Pointer(buf), C.int(size))

	if !bytes.HasPrefix(pb, []byte{0x04}) {
		return fmt.Errorf("bad key format")
	}
	if len(pb) != 65 {
		return fmt.Errorf("wanted public key data len 65, got: %d", len(pb))
	}
	k.pub = &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(pb[1:33]),
		Y:     big.NewInt(0).SetBytes(pb[33:]),
	}

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
