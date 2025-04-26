package seidentity

/*
#cgo CFLAGS: -Wno-unused-command-line-argument -fobjc-arc -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication

#include <stdlib.h> // For C.free
#include "SEIdentityCreator.h"
*/
import "C" // Import C symbols

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big" // Needed for parsing signature R, S and low-S check
	"unsafe"   // Required for Cgo pointer handling
)

// RFC 2986 CertificationRequestInfo
type certificationRequestInfo struct {
	Version       int
	Subject       asn1.RawValue
	SubjectPKInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	} // implicit sequence
	Attributes []attributeTypeAndValueSET `asn1:"tag:0"` // Context-specific tag 0 for Attributes
}

// Define pkix.AttributeTypeAndValueSET if not available or for clarity
// (based on crypto/x509/pkix types)
type attributeTypeAndValue struct {
	Type  asn1.ObjectIdentifier
	Value asn1.RawValue
}

type attributeTypeAndValueSET struct {
	Type  asn1.ObjectIdentifier
	Value [][]attributeTypeAndValue `asn1:"set"`
}

// ecdsaSignature is a helper struct for ASN.1 parsing ECDSA signatures
type ecdsaSignature struct {
	R, S *big.Int
}

// Error mapping from C error codes
var cErrorMap = map[C.int]error{
	C.SE_SUCCESS:                nil,
	C.SE_ERR_ACCESS_CONTROL:     errors.New("failed to create SecAccessControl"),
	C.SE_ERR_KEY_GENERATION:     errors.New("failed to generate SE key pair"),
	C.SE_ERR_KEY_QUERY_FAILED:   errors.New("failed to query keychain item (key, cert, or identity)"),
	C.SE_ERR_KEY_NOT_FOUND:      errors.New("SE private key not found"),
	C.SE_ERR_PUBKEY_EXPORT:      errors.New("failed to export SE public key"),
	C.SE_ERR_SIGNATURE_FAILED:   errors.New("failed to sign data/digest with SE key"),
	C.SE_ERR_CERT_CREATE_FAILED: errors.New("failed to create SecCertificateRef from DER"),
	C.SE_ERR_CERT_ADD_FAILED:    errors.New("failed to add/update certificate in Keychain"),
	C.SE_ERR_INVALID_INPUT:      errors.New("invalid input provided to C function"),
	C.SE_ERR_AUTH_FAILED:        errors.New("user failed or cancelled biometric authentication"),
	C.SE_ERR_UNKNOWN:            errors.New("unknown C error"),
}

// SecureEnclaveSigner implements crypto.Signer using a Secure Enclave key.
// Note: Assumes the key identified by KeyLabel exists and is accessible.
type SecureEnclaveSigner struct {
	publicKey crypto.PublicKey
	keyLabel  string
}

// NewSecureEnclaveSigner creates a signer instance.
// It currently requires the public key to be passed in, as fetching it dynamically
// within the Signer methods isn't implemented yet.
func NewSecureEnclaveSigner(label string, pub crypto.PublicKey) (*SecureEnclaveSigner, error) {
	// We could add a check here to ensure the key label exists, but for now,
	// assume it does and errors will occur during Sign().
	if pub == nil {
		return nil, errors.New("public key cannot be nil")
	}
	return &SecureEnclaveSigner{
		publicKey: pub,
		keyLabel:  label,
	}, nil
}

// Public returns the public key corresponding to the opaque private key.
func (s *SecureEnclaveSigner) Public() crypto.PublicKey {
	return s.publicKey
}

// Sign signs the provided digest using the Secure Enclave key.
// It ignores the rand io.Reader. The opts parameter is used to verify the hash algorithm.
// It also enforces low-S signature values as required by Go's verifier.
func (s *SecureEnclaveSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	// Verify hash algorithm (we only support SHA256 with the C function)
	if opts == nil || opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("unsupported hash function: %v, only SHA256 is supported", opts.HashFunc())
	}
	if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("invalid digest size: expected %d, got %d", crypto.SHA256.Size(), len(digest))
	}

	log.Printf("SecureEnclaveSigner: Signing digest for key label '%s'", s.keyLabel)

	cKeyLabel := C.CString(s.keyLabel)
	defer C.free(unsafe.Pointer(cKeyLabel))

	var cSignature *C.uchar
	var cSignatureLen C.size_t

	// Ensure digest is not empty before taking address
	if len(digest) == 0 {
		return nil, errors.New("digest cannot be empty")
	}
	cDigest := (*C.uchar)(unsafe.Pointer(&digest[0]))
	cDigestLen := C.size_t(len(digest))

	// Call the C function that signs the digest
	ret := C.SignDigestWithSEKey(cKeyLabel, cDigest, cDigestLen, &cSignature, &cSignatureLen)
	if ret != C.SE_SUCCESS {
		err := cErrorToGoError(ret)
		log.Printf("SecureEnclaveSigner: C.SignDigestWithSEKey failed for label '%s': %v", s.keyLabel, err)
		return nil, fmt.Errorf("seidentity: C.SignDigestWithSEKey failed: %w", err)
	}
	if cSignature == nil || cSignatureLen == 0 {
		log.Printf("SecureEnclaveSigner: C.SignDigestWithSEKey returned success but signature is nil/empty for label '%s'", s.keyLabel)
		return nil, errors.New("seidentity: C.SignDigestWithSEKey returned nil signature")
	}
	defer C.free(unsafe.Pointer(cSignature))

	signatureBytes := C.GoBytes(unsafe.Pointer(cSignature), C.int(cSignatureLen))
	log.Printf("SecureEnclaveSigner: Successfully signed digest for key label '%s', signature length: %d", s.keyLabel, len(signatureBytes))

	// --- Parse and enforce low-S signature values ---
	var parsedSig ecdsaSignature
	rest, err := asn1.Unmarshal(signatureBytes, &parsedSig)
	if err != nil {
		log.Printf("SecureEnclaveSigner: Failed to ASN.1 unmarshal signature from C: %v. Bytes: %x", err, signatureBytes)
		// Return original bytes if parsing failed, maybe verification will work somehow?
		return signatureBytes, nil
	} else if len(rest) > 0 {
		log.Printf("SecureEnclaveSigner: Trailing data after ASN.1 unmarshalling signature from C (%d bytes): %x", len(rest), rest)
		// Return original bytes if parsing had leftovers
		return signatureBytes, nil
	} else {
		log.Printf("SecureEnclaveSigner: Successfully ASN.1 unmarshalled signature. R=%s, S=%s", parsedSig.R.Text(16), parsedSig.S.Text(16))
	}

	// Prepare bytes for verification/return
	curve := elliptic.P256() // Assuming P256 based on key generation
	curveN := curve.Params().N
	halfN := new(big.Int).Div(curveN, big.NewInt(2))

	var finalSignatureBytes []byte

	if parsedSig.S.Cmp(halfN) > 0 {
		// S is high, replace with N - S
		log.Printf("SecureEnclaveSigner: Original S value (%s) is high. Normalizing to low-S.", parsedSig.S.Text(16))
		parsedSig.S.Sub(curveN, parsedSig.S)
		log.Printf("SecureEnclaveSigner: Normalized S value: %s", parsedSig.S.Text(16))

		// Re-marshal the signature with the low-S value
		normalizedBytes, errMarshal := asn1.Marshal(parsedSig)
		if errMarshal != nil {
			log.Printf("SecureEnclaveSigner: Failed to re-marshal low-S signature: %v", errMarshal)
			return nil, fmt.Errorf("failed to marshal low-s signature: %w", errMarshal)
		}
		finalSignatureBytes = normalizedBytes
		log.Printf("SecureEnclaveSigner: Using normalized low-S signature for verification/return. Length: %d", len(finalSignatureBytes))
	} else {
		// S was already low
		log.Printf("SecureEnclaveSigner: S value (%s) is already low. Using original signature for verification/return.", parsedSig.S.Text(16))
		finalSignatureBytes = signatureBytes
	}

	// --- Optional Debug: Explicit Verification Step ---
	ecdsaPubKey, ok := s.publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.Printf("SecureEnclaveSigner: Public key is not ECDSA (*ecdsa.PublicKey), cannot verify locally.")
	} else {
		verified := ecdsa.VerifyASN1(ecdsaPubKey, digest, finalSignatureBytes)
		if verified {
			log.Printf("SecureEnclaveSigner: <<< LOCAL VERIFICATION SUCCEEDED >>>")
		} else {
			log.Printf("SecureEnclaveSigner: <<< LOCAL VERIFICATION FAILED >>>")
			// If local verification fails, the signature is fundamentally wrong.
			return nil, errors.New("seidentity: locally generated signature failed local verification")
		}
	}
	// --- End Debug ---

	// Return the final signature bytes (normalized or original)
	return finalSignatureBytes, nil
}

// CreateKeyCSR creates a CSR for the given request, provisioning a new SE key pair.
// It uses a crypto.Signer wrapping the SE key.
func CreateKeyCSR(req *x509.CertificateRequest, keyLabel string) ([]byte, error) {

	log.Printf("Using Keychain Label: %s", keyLabel)

	// --- Step 1: Generate SE Key Pair and Get Public Key ---
	log.Println("Step 1: Generating Secure Enclave key pair and getting public key...")
	cKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(cKeyLabel))

	var cPubKeyDER *C.uchar
	var cPubKeyLen C.size_t

	ret := C.GenerateSEKeyPairAndGetPublicKey(cKeyLabel, &cPubKeyDER, &cPubKeyLen)
	if ret != C.SE_SUCCESS {
		return nil, fmt.Errorf("error generating key pair: %w", cErrorToGoError(ret))
	}
	if cPubKeyDER == nil || cPubKeyLen == 0 {
		return nil, errors.New("C function returned success but public key is nil or empty")
	}
	defer C.free(unsafe.Pointer(cPubKeyDER))

	// Convert C buffer to Go slice (raw key bytes)
	rawPublicKeyBytes := C.GoBytes(unsafe.Pointer(cPubKeyDER), C.int(cPubKeyLen))
	log.Printf("Raw Public Key bytes length: %d", len(rawPublicKeyBytes))

	// Reconstruct the ECDSA public key from raw bytes
	curve := elliptic.P256()
	x, y := elliptic.Unmarshal(curve, rawPublicKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("error unmarshalling raw public key bytes from SE for curve P256. Length: %d, Bytes (first 10): %x", len(rawPublicKeyBytes), rawPublicKeyBytes[:min(10, len(rawPublicKeyBytes))])
	}
	ecdsaPubKey := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	log.Printf("Reconstructed ECDSA public key. Curve: %s", ecdsaPubKey.Curve.Params().Name)

	// --- Step 2: Create Secure Enclave Signer ---
	log.Println("Step 2: Creating Secure Enclave signer...")
	seSigner, err := NewSecureEnclaveSigner(keyLabel, ecdsaPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Secure Enclave signer: %w", err)
	}

	// --- Step 3: Prepare CSR Template ---
	// Note: The PublicKey field in the template is ignored by CreateCertificateRequest
	// when a Signer is provided; it uses signer.Public().
	// We *must* specify the SignatureAlgorithm.
	req.SignatureAlgorithm = x509.ECDSAWithSHA256
	// Ensure other fields like Subject, SANs etc. are set correctly in the input `req`.
	log.Printf("Prepared CSR template with Subject: %s, SignatureAlgorithm: %s", req.Subject.String(), req.SignatureAlgorithm)

	// --- Step 4: Create CSR using the Signer ---
	log.Println("Step 4: Calling x509.CreateCertificateRequest with SE signer...")
	// This will call seSigner.Sign(), which triggers the C function and potentially biometric auth.
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, req, seSigner)
	if err != nil {
		// Log the error details, including any underlying C error from the signer
		log.Printf("Error during x509.CreateCertificateRequest: %v", err)
		return nil, fmt.Errorf("failed to create CSR using SE signer: %w", err)
	}
	log.Println("Successfully created CSR DER using SE signer.")

	// --- Step 5: Encode CSR to PEM ---
	log.Println("Step 5: Encoding CSR to PEM format...")
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	log.Printf("Successfully encoded CSR to PEM. Length: %d bytes", len(csrPEM))

	return csrPEM, nil
}

// ProvisionKeychainIdentity provisions the keychain with the signed certificate.
// (No changes needed here)
func ProvisionKeychainIdentity(keyLabel string, signedCertDER []byte) error {

	// Convert keyLabel to C string
	cKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(cKeyLabel))

	// --- Step 7: Provision Keychain Identity via Cgo ---
	log.Println("Step 7: Provisioning Keychain identity with the certificate...")

	if len(signedCertDER) == 0 {
		return errors.New("seidentity: signed certificate DER cannot be empty")
	}
	cCertDER := (*C.uchar)(unsafe.Pointer(&signedCertDER[0]))
	cCertLen := C.size_t(len(signedCertDER))

	ret := C.ProvisionIdentityWithCertificate(cKeyLabel, cCertDER, cCertLen)
	if ret != C.SE_SUCCESS {
		return fmt.Errorf("error provisioning identity: %w", cErrorToGoError(ret))
	}

	return nil
}

// Convert C error code to Go error
func cErrorToGoError(status C.int) error {
	// Use the map first for cleaner mapping
	if err, ok := cErrorMap[status]; ok {
		// If err is nil (for SE_SUCCESS), return nil directly
		if err == nil {
			return nil
		}
		// Otherwise, return the mapped error
		return err
	}
	// Fallback for unexpected codes
	return fmt.Errorf("seidentity: unexpected status code: %d", status)
}

// KeyInfo holds the label and tag for a Secure Enclave key.
type KeyInfo struct {
	Label string
	Tag   []byte
}

// ListSecureEnclaveKeyInfos retrieves the label and tag of all keys provisioned
// in the Secure Enclave by this application matching the query criteria.
func ListSecureEnclaveKeyInfos() ([]KeyInfo, error) {
	var cKeyInfos *C.SEKeyInfo
	var cCount C.int

	status := C.ListSEKeyInfos(&cKeyInfos, &cCount)
	err := cErrorToGoError(status)
	if err != nil {
		// Assume C.ListSEKeyInfos cleans up if it returns an error status.
		return nil, fmt.Errorf("failed to list SE key infos: %w", err)
	}

	// Ensure the C memory is freed.
	if cKeyInfos != nil {
		defer C.FreeSEKeyInfoList(cKeyInfos, cCount)
	}

	if cCount == 0 {
		return []KeyInfo{}, nil // Return empty slice, not nil
	}

	// Convert C array of structs to Go slice of structs
	goKeyInfos := make([]KeyInfo, 0, int(cCount))

	// Create a Go slice header backed by the C array data
	cKeyInfoSlice := (*[1 << 30]C.SEKeyInfo)(unsafe.Pointer(cKeyInfos))[:cCount:cCount]

	for i := 0; i < int(cCount); i++ {
		info := KeyInfo{}
		if cKeyInfoSlice[i].label != nil {
			info.Label = C.GoString(cKeyInfoSlice[i].label)
		}
		if cKeyInfoSlice[i].tagData != nil && cKeyInfoSlice[i].tagLength > 0 {
			// Use C.GoBytes to copy the tag data
			info.Tag = C.GoBytes(cKeyInfoSlice[i].tagData, C.int(cKeyInfoSlice[i].tagLength))
		}
		goKeyInfos = append(goKeyInfos, info)
	}

	return goKeyInfos, nil
}

// Helper function to find minimum of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// KeychainIdentityInfo holds information about a keychain identity suitable for mTLS.
type KeychainIdentityInfo struct {
	Label       string            // The kSecAttrLabel used to provision the key/cert.
	Certificate *x509.Certificate // The parsed client certificate.
	Signer      crypto.Signer     // A crypto.Signer using the Secure Enclave key.
}

// ListKeychainIdentities retrieves information about all identities (certificate + private key)
// available to the application in the macOS Keychain.
func ListKeychainIdentities() ([]KeychainIdentityInfo, error) {
	var cIdentityInfos *C.KeychainIdentityInfo
	var cCount C.int

	status := C.ListKeychainIdentities(&cIdentityInfos, &cCount)
	err := cErrorToGoError(status)
	if err != nil {
		// C function expected to handle cleanup on error return
		return nil, fmt.Errorf("failed to list keychain identities: %w", err)
	}

	// Ensure the C memory allocated by ListKeychainIdentities is freed
	if cIdentityInfos != nil {
		defer C.FreeKeychainIdentityInfoList(cIdentityInfos, cCount)
	}

	if cCount == 0 {
		return []KeychainIdentityInfo{}, nil // Return empty slice, not nil
	}

	// Convert C array of structs to Go slice
	goIdentityInfos := make([]KeychainIdentityInfo, 0, int(cCount))

	// Create a Go slice header backed by the C array data
	// #nosec G103 -- unsafe pointer is necessary for CGo interaction here. Lifespan is controlled.
	cIdentityInfoSlice := (*[1 << 30]C.KeychainIdentityInfo)(unsafe.Pointer(cIdentityInfos))[:cCount:cCount]

	for i := 0; i < int(cCount); i++ {
		ci := cIdentityInfoSlice[i]
		info := KeychainIdentityInfo{}

		// 1. Get the Label
		if ci.label == nil {
			log.Printf("Warning: Keychain identity at index %d has nil label from C, skipping.", i)
			continue
		}
		info.Label = C.GoString(ci.label)

		// 2. Get and Parse the Certificate
		if ci.certificateDER == nil || ci.certificateDERLength == 0 {
			log.Printf("Warning: Keychain identity '%s' (index %d) has nil/empty certificate DER from C, skipping.", info.Label, i)
			continue
		}
		certDER := C.GoBytes(unsafe.Pointer(ci.certificateDER), C.int(ci.certificateDERLength))
		parsedCert, err := x509.ParseCertificate(certDER)
		if err != nil {
			log.Printf("Warning: Failed to parse certificate DER for identity '%s' (index %d): %v, skipping.", info.Label, i, err)
			continue
		}
		info.Certificate = parsedCert

		// 3. Create the Signer
		// Extract the public key from the certificate.
		// We assume it's ECDSA P-256, consistent with key generation.
		ecdsaPubKey, ok := parsedCert.PublicKey.(*ecdsa.PublicKey)
		if !ok || ecdsaPubKey.Curve.Params().Name != elliptic.P256().Params().Name {
			log.Printf("Warning: Certificate for identity '%s' (index %d) does not contain a P-256 ECDSA public key, skipping.", info.Label, i)
			continue
		}

		// Create the SecureEnclaveSigner using the label and the public key from the cert.
		seSigner, err := NewSecureEnclaveSigner(info.Label, ecdsaPubKey)
		if err != nil {
			// This shouldn't typically fail if the label is correct and pubkey is provided,
			// but handle defensively.
			log.Printf("Warning: Failed to create SecureEnclaveSigner for identity '%s' (index %d): %v, skipping.", info.Label, i, err)
			continue
		}
		info.Signer = seSigner

		// If all steps succeeded, add to the results
		goIdentityInfos = append(goIdentityInfos, info)
	}

	return goIdentityInfos, nil
}
