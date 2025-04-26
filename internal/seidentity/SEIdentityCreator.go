package seidentity

/*
#cgo CFLAGS: -Wno-unused-command-line-argument -fobjc-arc -x objective-c
#cgo LDFLAGS: -framework Foundation -framework Security -framework LocalAuthentication -L. -lSEIdentityCreator

#include <stdlib.h> // For C.free
#include "SEIdentityCreator.h"
*/
import "C" // Import C symbols

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"os"
	"time"
	"unsafe" // Required for Cgo pointer handling
)

// Error mapping from C error codes
var cErrorMap = map[C.int]error{
	C.SE_SUCCESS:                nil,
	C.SE_ERR_ACCESS_CONTROL:     errors.New("failed to create SecAccessControl"),
	C.SE_ERR_KEY_GENERATION:     errors.New("failed to generate SE key pair"),
	C.SE_ERR_KEY_QUERY_FAILED:   errors.New("failed to query SE private key"),
	C.SE_ERR_KEY_NOT_FOUND:      errors.New("SE private key not found"),
	C.SE_ERR_PUBKEY_EXPORT:      errors.New("failed to export SE public key"),
	C.SE_ERR_SIGNATURE_FAILED:   errors.New("failed to sign data with SE key"),
	C.SE_ERR_CERT_CREATE_FAILED: errors.New("failed to create SecCertificateRef from DER"),
	C.SE_ERR_CERT_ADD_FAILED:    errors.New("failed to add/update certificate in Keychain"),
	C.SE_ERR_INVALID_INPUT:      errors.New("invalid input provided to C function"),
	C.SE_ERR_AUTH_FAILED:        errors.New("user failed or cancelled biometric authentication"),
	C.SE_ERR_UNKNOWN:            errors.New("unknown C error"),
}

func main() {
	keyLabel := "com.example.mysekey.mtls-" + time.Now().Format("20060102150405")
	log.Printf("Using Keychain Label: %s", keyLabel)

	// --- Step 1: Generate SE Key Pair and Get Public Key ---
	log.Println("Step 1: Generating Secure Enclave key pair...")
	cKeyLabel := C.CString(keyLabel)
	defer C.free(unsafe.Pointer(cKeyLabel))

	var cPubKeyDER *C.uchar
	var cPubKeyLen C.size_t

	ret := C.GenerateSEKeyPairAndGetPublicKey(cKeyLabel, &cPubKeyDER, &cPubKeyLen)
	if ret != C.SE_SUCCESS {
		log.Fatalf("Error generating key pair: %v", cErrorMap[ret])
	}
	if cPubKeyDER == nil || cPubKeyLen == 0 {
		log.Fatalf("C function returned success but public key is nil or empty")
	}
	defer C.free(unsafe.Pointer(cPubKeyDER)) // Free memory allocated by C

	// Convert C buffer to Go slice
	publicKeyDER := C.GoBytes(unsafe.Pointer(cPubKeyDER), C.int(cPubKeyLen))
	log.Printf("Successfully generated key pair. Public Key DER length: %d", len(publicKeyDER))

	// Parse the public key
	pubKey, err := x509.ParsePKIXPublicKey(publicKeyDER)
	if err != nil {
		log.Fatalf("Error parsing public key DER: %v", err)
	}
	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public key is not an ECDSA key: %T", pubKey)
	}
	log.Printf("Parsed public key type: %T", ecdsaPubKey)

	// --- Step 2: Create CSR Template in Go ---
	log.Println("Step 2: Creating CSR template...")
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"Example Org"},
			OrganizationalUnit: []string{"Example Unit"},
			Country:            []string{"DE"}, // Germany
			Province:           []string{"Berlin"},
			Locality:           []string{"Berlin"},
			CommonName:         "My SE Device " + time.Now().Format("150405"),
		},
		// DNSNames:    []string{"device.example.com"}, // Optional
		// EmailAddresses: []string{"device@example.com"}, // Optional
		SignatureAlgorithm: x509.ECDSAWithSHA256, // Must match key type and signing hash
	}

	// --- Step 3: Get TBS (To-Be-Signed) data for the CSR ---
	log.Println("Step 3: Generating TBS data for CSR...")
	// We need to create the TBS structure manually or use CreateCertificateRequest
	// with a dummy signer just to get the structure, then sign externally.
	// Let's use CreateCertificateRequest with a dummy signer.
	dummyPrivKey, _ := ecdsa.GenerateKey(ecdsa.P256(), rand.Reader) // Temporary key
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, dummyPrivKey)
	if err != nil {
		log.Fatalf("Error creating dummy CSR DER: %v", err)
	}

	// Parse the dummy CSR to extract the TBS part
	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		log.Fatalf("Error parsing dummy CSR DER: %v", err)
	}
	if err = parsedCSR.CheckSignature(); err == nil {
		log.Println("Warning: Dummy CSR signature check passed unexpectedly (should ideally fail or be ignored)")
	} else {
		log.Printf("Dummy CSR signature check failed as expected: %v", err)
	}

	// The TBSCertificateRequest structure is embedded within the parsed CSR.
	// We need the raw bytes of this part.
	tbsCSRContents := parsedCSR.RawTBSCertificateRequest
	log.Printf("TBS CSR data length: %d", len(tbsCSRContents))

	// --- Step 4: Sign TBS Data using SE Key via Cgo ---
	log.Println("Step 4: Signing TBS data with Secure Enclave key (will likely require Touch ID/Face ID)...")
	var cSignature *C.uchar
	var cSignatureLen C.size_t

	// Convert Go slice to C buffer (no copy needed for input)
	cDataToSign := (*C.uchar)(unsafe.Pointer(&tbsCSRContents[0]))
	cDataLen := C.size_t(len(tbsCSRContents))

	ret = C.SignDataWithSEKey(cKeyLabel, cDataToSign, cDataLen, &cSignature, &cSignatureLen)
	if ret != C.SE_SUCCESS {
		log.Fatalf("Error signing data: %v", cErrorMap[ret])
	}
	if cSignature == nil || cSignatureLen == 0 {
		log.Fatalf("C function returned success but signature is nil or empty")
	}
	defer C.free(unsafe.Pointer(cSignature))

	signatureBytes := C.GoBytes(unsafe.Pointer(cSignature), C.int(cSignatureLen))
	log.Printf("Successfully signed data. Signature length: %d", len(signatureBytes))

	// --- Step 5: Assemble Final Signed CSR ---
	log.Println("Step 5: Assembling final signed CSR...")
	// The final CSR structure is: CertificateRequest SEQUENCE {
	//      tbsCertificateRequest TBSCertificateRequest,
	//      signatureAlgorithm    AlgorithmIdentifier,
	//      signature             BIT STRING
	// }
	// We already have the tbsCertificateRequest bytes (tbsCSRContents)
	// We need the signatureAlgorithm identifier (use the one from the parsed dummy CSR)
	// We have the signatureBytes.

	finalCSR := struct {
		TBSCertificateRequest asn1.RawValue
		SignatureAlgorithm    pkix.AlgorithmIdentifier
		SignatureValue        asn1.BitString
	}{
		TBSCertificateRequest: asn1.RawValue{FullBytes: tbsCSRContents},
		SignatureAlgorithm:    parsedCSR.SignatureAlgorithm, // From the dummy parsed CSR
		SignatureValue:        asn1.BitString{Bytes: signatureBytes, BitLength: len(signatureBytes) * 8},
	}

	finalCSRDER, err := asn1.Marshal(finalCSR)
	if err != nil {
		log.Fatalf("Error marshaling final CSR: %v", err)
	}
	log.Println("Successfully assembled final CSR.")

	// Save CSR to file (optional)
	csrFilename := "se_key_csr.pem"
	csrFile, err := os.Create(csrFilename)
	if err != nil {
		log.Printf("Warning: Could not create CSR file: %v", err)
	} else {
		defer csrFile.Close()
		pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: finalCSRDER})
		log.Printf("Saved CSR to %s", csrFilename)
	}

	// --- Step 6: (SIMULATED) Get CSR Signed by CA ---
	log.Println("Step 6: SIMULATING CA Signing...")
	// In a real scenario, you would send `finalCSRDER` to your CA
	// and receive back a signed certificate in DER format.
	// For this example, we will self-sign using a temporary Go key.
	// DO NOT use this self-signed cert for real mTLS unless the server trusts the dummy CA.
	caPrivKey, _ := ecdsa.GenerateKey(ecdsa.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Dummy CA"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	// Create a certificate template based on the CSR
	certTemplate := &x509.Certificate{
		Version:            parsedCSR.Version, // Use version from CSR
		SerialNumber:       big.NewInt(2),     // Unique serial
		Subject:            parsedCSR.Subject, // Use subject from CSR
		PublicKeyAlgorithm: parsedCSR.PublicKeyAlgorithm,
		PublicKey:          ecdsaPubKey,          // The actual SE public key
		SignatureAlgorithm: x509.ECDSAWithSHA256, // CA signing algorithm
		NotBefore:          time.Now().Add(-10 * time.Minute),
		NotAfter:           time.Now().Add(24 * time.Hour * 90), // 90 days validity
		KeyUsage:           x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // For mTLS
		// DNSNames:        parsedCSR.DNSNames, // Copy relevant fields
		// EmailAddresses: parsedCSR.EmailAddresses,
	}

	signedCertDER, err := x509.CreateCertificate(rand.Reader, certTemplate, caTemplate, ecdsaPubKey, caPrivKey)
	if err != nil {
		log.Fatalf("Error creating self-signed certificate: %v", err)
	}
	log.Printf("Successfully created (self-signed) certificate. DER length: %d", len(signedCertDER))

	// Save certificate (optional)
	certFilename := "se_key_cert.pem"
	certFile, err := os.Create(certFilename)
	if err != nil {
		log.Printf("Warning: Could not create certificate file: %v", err)
	} else {
		defer certFile.Close()
		pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: signedCertDER})
		log.Printf("Saved certificate to %s", certFilename)
	}

	// --- Step 7: Provision Keychain Identity via Cgo ---
	log.Println("Step 7: Provisioning Keychain identity with the certificate...")

	cCertDER := (*C.uchar)(unsafe.Pointer(&signedCertDER[0]))
	cCertLen := C.size_t(len(signedCertDER))

	ret = C.ProvisionIdentityWithCertificate(cKeyLabel, cCertDER, cCertLen)
	if ret != C.SE_SUCCESS {
		log.Fatalf("Error provisioning identity: %v", cErrorMap[ret])
	}

	log.Println("--- SUCCESS ---")
	log.Printf("Keychain identity provisioned with label: %s", keyLabel)
	log.Println("You should now be able to see this identity in Keychain Access.")
	log.Println("Applications like Chrome/Safari should be able to use it for mTLS if prompted by a server.")
	log.Println("Note: Biometric confirmation (Touch ID/Face ID) will likely be required each time the key is used for signing.")
}

// Helper function to calculate SHA256 hash
func calculateSHA256(data []byte) []byte {
	hasher := sha256.New()
	hasher.Write(data)
	return hasher.Sum(nil)
}
