package main

/*
	#cgo CFLAGS: -x objective-c -Wno-deprecated-declarations
	#cgo LDFLAGS: -framework Security -framework Foundation

	#include <CoreFoundation/CoreFoundation.h>
	#include <Security/Security.h>
	#include <Security/SecPolicy.h> // For SecPolicy
	#include <Security/SecTrust.h>  // For SecTrust
	#include <Foundation/Foundation.h> // For NSLog

	// --- Helper Functions ---

	// Helper to create CFDataRef from bytes (caller must CFRelease)
	CFDataRef CreateCFData(const unsigned char *bytes, CFIndex length) {
	    if (bytes == NULL) {
	        return NULL;
	    }
	    return CFDataCreate(kCFAllocatorDefault, bytes, length);
	}

	// Helper function to convert CFStringRef to CFDataRef (caller must CFRelease)
	CFDataRef CFStringCreateData(CFAllocatorRef allocator, CFStringRef string, CFStringEncoding encoding) {
	    if (string == NULL) {
	        return NULL;
	    }
	    CFIndex length = CFStringGetLength(string);
	    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, encoding);
	    UInt8 *buffer = (UInt8 *)malloc(maxSize);
	    if (!buffer) {
	        return NULL;
	    }
	    CFIndex actualSize;
	    CFStringGetBytes(string, CFRangeMake(0, length), encoding, 0, false, buffer, maxSize, &actualSize);
	    CFDataRef data = CFDataCreate(allocator, buffer, actualSize);
	    free(buffer);
	    return data;
	}

	// Helper: Logs a message prefixed with [CGO]
	void CLog(const char *format, ...) {
	    va_list args;
	    va_start(args, format);

	    char buffer[1024];
	    vsnprintf(buffer, sizeof(buffer), format, args);

	    // Create an NSString from the buffer to use with NSLog
	    NSString *nsMessage = [NSString stringWithUTF8String:buffer];
	    NSLog(@"[CGO] %@", nsMessage);
	    va_end(args);
	}

	// Helper: Deletes a keychain item (key or certificate) by application tag
	OSStatus DeleteKeychainItemByTag(CFDataRef appTagData, CFTypeRef itemClass) {
	    CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	                                                             &kCFTypeDictionaryKeyCallBacks,
	                                                             &kCFTypeDictionaryValueCallBacks);
	    if (!query) return errSecAllocate;

	    CFDictionarySetValue(query, kSecClass, itemClass);
	    CFDictionarySetValue(query, kSecAttrApplicationTag, appTagData);
	    // If deleting a key, specify type and token ID for precision
	    if (itemClass == kSecClassKey) {
	        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
	        CFDictionarySetValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
	    }

	    OSStatus status = SecItemDelete(query);
	    CFRelease(query);

	    if (status != errSecSuccess && status != errSecItemNotFound) {
	        CLog("Error deleting existing item (tag: %s, class: %s): %d",
	             (const char*)CFDataGetBytePtr(appTagData), // Assumes tag is printable UTF8 - BE CAREFUL
	             (itemClass == kSecClassKey) ? "Key" : "Cert",
	             (int)status);
	    } else {
	         CLog("Attempted deletion of item (tag: %s, class: %s): Status %d (Ignored if not found)",
	             (const char*)CFDataGetBytePtr(appTagData),
	             (itemClass == kSecClassKey) ? "Key" : "Cert",
	             (int)status);
	    }
	    // Treat 'not found' as success in this context
	    return (status == errSecItemNotFound) ? errSecSuccess : status;
	}

	// Helper: Convert CFString to Go-compatible C string
	char* CFStringToUTF8CString(CFStringRef cfStr) {
	    if (cfStr == NULL) return NULL;

	    CFIndex length = CFStringGetLength(cfStr);
	    CFIndex maxSize = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
	    char* buffer = (char*)malloc(maxSize);

	    if (buffer == NULL) return NULL;

	    if (!CFStringGetCString(cfStr, buffer, maxSize, kCFStringEncodingUTF8)) {
	        free(buffer); // Failed to convert
	        return NULL;
	    }

	    return buffer;
	    // Caller must free this memory
	}

	// --- Implemented CGO Functions ---

	// Generates a P-256 key pair in Secure Enclave, stores persistently, tagged by appTagData.
	// Returns public key DER bytes or NULL on error. Caller must free the returned buffer if not NULL.
	CFDataRef generateSEKeyPair_internal(CFDataRef appTagData) {
	    OSStatus status = noErr;
	    CFErrorRef error = NULL;
	    SecAccessControlRef sacObject = NULL;
	    CFMutableDictionaryRef privateKeyAttrs = NULL;
	    CFMutableDictionaryRef attributes = NULL;
	    SecKeyRef privateKey = NULL;
	    SecKeyRef publicKey = NULL;
	    CFDataRef publicKeyData = NULL;

	    CLog("generateSEKeyPair_internal: Starting for tag: %s", (const char*)CFDataGetBytePtr(appTagData)); // BE CAREFUL about tag content

	    // 0. Delete existing key first to avoid errSecDuplicateItem
	    status = DeleteKeychainItemByTag(appTagData, kSecClassKey);
	    if (status != errSecSuccess) {
	        CLog("generateSEKeyPair_internal: Failed initial delete (continuing anyway): %d", (int)status);
	        // Don't necessarily fail here, SecKeyCreateRandomKey might handle it or fail appropriately
	    }

	    // 1. Create Access Control: Protect with passcode/biometry, requires private key usage.
	    // kSecAttrAccessibleWhenUnlockedThisDeviceOnly is often preferred for SE keys.
	    sacObject = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
	                                                kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // Only usable on this device when unlocked
	                                                kSecAccessControlPrivateKeyUsage,           // Allow signing/decrypt operations
	                                                &error);
	    if (error != NULL || sacObject == NULL) {
	        NSString *errorDesc = error ? CFBridgingRelease(CFErrorCopyDescription(error)) : @"Unknown error";
	        CLog("generateSEKeyPair_internal: SecAccessControlCreateWithFlags failed: %s", [errorDesc UTF8String]);
	        goto cleanup;
	    }

	    // 2. Define Private Key Attributes dictionary
	    privateKeyAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	                                                &kCFTypeDictionaryKeyCallBacks,
	                                                &kCFTypeDictionaryValueCallBacks);
	    if (!privateKeyAttrs) { status = errSecAllocate; goto cleanup; }
	    CFDictionarySetValue(privateKeyAttrs, kSecAttrIsPermanent, kCFBooleanTrue);        // Store permanently in Keychain
	    CFDictionarySetValue(privateKeyAttrs, kSecAttrApplicationTag, appTagData);        // Tag the key
	    CFDictionarySetValue(privateKeyAttrs, kSecAttrAccessControl, sacObject);          // Apply access control

	    // 3. Define Overall Key Generation Attributes dictionary
	    attributes = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	                                           &kCFTypeDictionaryKeyCallBacks,
	                                           &kCFTypeDictionaryValueCallBacks);
	    if (!attributes) { status = errSecAllocate; goto cleanup; }
	    CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom); // Key type: ECC P-256
	    // Create number directly instead of using Objective-C literal
	    int keySize = 256;
	    CFNumberRef keySizeRef = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &keySize);
	    CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, keySizeRef); // Key size: 256 bits
	    CFRelease(keySizeRef); // Release since dictionary keeps a reference
	    CFDictionarySetValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);   // Specify Secure Enclave
	    CFDictionarySetValue(attributes, kSecPrivateKeyAttrs, privateKeyAttrs);            // Embed private key attrs

	    // 4. Generate Key Pair
	    privateKey = SecKeyCreateRandomKey(attributes, &error);
	    if (error != NULL || privateKey == NULL) {
	        NSString *errorDesc = error ? CFBridgingRelease(CFErrorCopyDescription(error)) : @"Unknown error";
	        CLog("generateSEKeyPair_internal: SecKeyCreateRandomKey failed: %s", [errorDesc UTF8String]);
	        goto cleanup;
	    }
	    CLog("generateSEKeyPair_internal: Secure Enclave key pair generated.");

	    // 5. Get Public Key reference
	    publicKey = SecKeyCopyPublicKey(privateKey);
	    if (publicKey == NULL) {
	        CLog("generateSEKeyPair_internal: SecKeyCopyPublicKey failed.");
	        status = errSecInternalError; // Or some other appropriate error
	        goto cleanup;
	    }
	     CLog("generateSEKeyPair_internal: Public key reference obtained.");

	    // 6. Export Public Key to DER format (X.509 SubjectPublicKeyInfo)
	    publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error);
	    if (error != NULL || publicKeyData == NULL) {
	        NSString *errorDesc = error ? CFBridgingRelease(CFErrorCopyDescription(error)) : @"Unknown error";
	        CLog("generateSEKeyPair_internal: SecKeyCopyExternalRepresentation failed: %s", [errorDesc UTF8String]);
	        // Keep publicKeyData as NULL, error will propagate
	    } else {
	         CLog("generateSEKeyPair_internal: Public key exported to DER (length %ld).", CFDataGetLength(publicKeyData));
	    }


	cleanup:
	    if (error) {
	        CFRelease(error); // Release error ref if it was created
	    }
	    if (sacObject) {
	        CFRelease(sacObject);
	    }
	    if (privateKeyAttrs) {
	        CFRelease(privateKeyAttrs);
	    }
	    if (attributes) {
	        CFRelease(attributes);
	    }
	    if (privateKey) {
	        CFRelease(privateKey); // Release the private key ref we got
	    }
	    if (publicKey) {
	        CFRelease(publicKey); // Release the public key ref we got
	    }
	    // IMPORTANT: Do NOT release publicKeyData if we are returning it successfully.
	    // The Go caller will receive ownership and must release it via defer C.CFRelease().

	    CLog("generateSEKeyPair_internal: Finished.");
	    return publicKeyData; // Will be NULL if any step failed and set it to NULL
	}


	// Finds the SE private key by tag and signs the dataDigest (SHA256).
	// Returns signature ASN.1 DER bytes or NULL on error. Caller must free returned buffer.
	CFDataRef signWithSEKey_internal(CFDataRef appTagData, CFDataRef dataDigestCF) {
	    OSStatus status = noErr;
	    CFErrorRef error = NULL;
	    CFMutableDictionaryRef query = NULL;
	    SecKeyRef privateKey = NULL;
	    CFDataRef signature = NULL;

	    CLog("signWithSEKey_internal: Starting for tag: %s", (const char*)CFDataGetBytePtr(appTagData));

	    // 1. Create Query Dictionary to find the private key
	    query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	                                      &kCFTypeDictionaryKeyCallBacks,
	                                      &kCFTypeDictionaryValueCallBacks);
	    if (!query) { status = errSecAllocate; goto cleanup; }
	    CFDictionarySetValue(query, kSecClass, kSecClassKey);                      // We want a key
	    CFDictionarySetValue(query, kSecAttrApplicationTag, appTagData);           // Matching our tag
	    CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom); // Specifically the ECC key
	    CFDictionarySetValue(query, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);   // Stored in Secure Enclave
	    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);                // Return the SecKeyRef

	    // 2. Find Private Key
	    status = SecItemCopyMatching(query, (CFTypeRef *)&privateKey);
	    if (status != errSecSuccess || privateKey == NULL) {
	        CLog("signWithSEKey_internal: SecItemCopyMatching failed to find private key: %d", (int)status);
	        goto cleanup;
	    }
	    CLog("signWithSEKey_internal: Private key reference obtained.");

	    // 3. Check if signing is possible with this key
	    bool canSign = SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, kSecKeyAlgorithmECDSASignatureDigestX962SHA256);
	     if (!canSign) {
	         CLog("signWithSEKey_internal: Key does not support signing with ECDSASignatureDigestX962SHA256.");
	         status = errSecAlgorithmMismatch; // Or another appropriate error
	         goto cleanup;
	     }
	      CLog("signWithSEKey_internal: Signing algorithm supported.");

	    // 4. Sign Digest
	    // Note: kSecKeyAlgorithmECDSASignatureDigestX962SHA256 expects the *raw SHA256 digest* as input.
	    signature = SecKeyCreateSignature(privateKey,
	                                      kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
	                                      dataDigestCF,
	                                      &error);

	    if (error != NULL || signature == NULL) {
	        NSString *errorDesc = error ? CFBridgingRelease(CFErrorCopyDescription(error)) : @"Unknown error";
	        CLog("signWithSEKey_internal: SecKeyCreateSignature failed: %s", [errorDesc UTF8String]);
	        // Ensure signature is NULL if error occurred
	        if (signature) { CFRelease(signature); signature = NULL; }
	    } else {
	        CLog("signWithSEKey_internal: Data signed successfully (signature length %ld).", CFDataGetLength(signature));
	    }

	cleanup:
	    if (error) {
	        CFRelease(error);
	    }
	    if (query) {
	        CFRelease(query);
	    }
	    if (privateKey) {
	        CFRelease(privateKey); // Release the key ref we obtained
	    }
	    // IMPORTANT: Do NOT release signature if returning successfully. Go caller owns it.

	    CLog("signWithSEKey_internal: Finished.");
	    return signature; // Will be NULL if any step failed
	}


	// Imports certificate, associates with key via appTag.
	OSStatus importCertificateAndAssociate_internal(CFDataRef appTagData, CFDataRef certDataCF) {
	    OSStatus status = noErr;
	    SecCertificateRef certRef = NULL;
	    CFMutableDictionaryRef addDict = NULL;
	    CFStringRef labelRef = NULL; // Optional label

	    CLog("importCertificateAndAssociate_internal: Starting for tag: %s", (const char*)CFDataGetBytePtr(appTagData));

	    // 0. Delete existing certificate first to avoid errSecDuplicateItem
	    // Note: This might be too aggressive if multiple certs could share a tag, but simplest for this example.
	    status = DeleteKeychainItemByTag(appTagData, kSecClassCertificate);
	    if (status != errSecSuccess) {
	         CLog("importCertificateAndAssociate_internal: Failed initial delete (continuing anyway): %d", (int)status);
	    }

	    // 1. Create SecCertificateRef from DER data
	    certRef = SecCertificateCreateWithData(NULL, certDataCF);
	    if (certRef == NULL) {
	        CLog("importCertificateAndAssociate_internal: SecCertificateCreateWithData failed.");
	        status = errSecDecode; // Example error
	        goto cleanup;
	    }
	     CLog("importCertificateAndAssociate_internal: SecCertificateRef created.");

	     // Optional: Get a label for the certificate (e.g., common name)
	     SecTrustRef trust = NULL;
	     SecPolicyRef policy = SecPolicyCreateBasicX509();
	     status = SecTrustCreateWithCertificates(certRef, policy, &trust);
	     if (status == errSecSuccess) {
	         SecCertificateRef evaluatedCert = SecTrustGetCertificateAtIndex(trust, 0); // Should be our cert
	         if (evaluatedCert) {
	            labelRef = SecCertificateCopySubjectSummary(evaluatedCert); // Get summary (like CN)
	            if (labelRef) {
	                NSString *labelStr = CFBridgingRelease(CFStringCreateCopy(kCFAllocatorDefault, labelRef));
	                CLog("importCertificateAndAssociate_internal: Using label: %s", [labelStr UTF8String]);
	            }
	         }
	         CFRelease(trust);
	     } else {
	         CLog("importCertificateAndAssociate_internal: Could not create trust for getting label: %d", (int)status);
	         // Continue without label
	     }
	     if (policy) CFRelease(policy);


	    // 2. Create Add Dictionary
	    addDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
	                                        &kCFTypeDictionaryKeyCallBacks,
	                                        &kCFTypeDictionaryValueCallBacks);
	    if (!addDict) { status = errSecAllocate; goto cleanup; }
	    CFDictionarySetValue(addDict, kSecClass, kSecClassCertificate);     // Item type is certificate
	    CFDictionarySetValue(addDict, kSecValueRef, certRef);               // The certificate data reference
	    CFDictionarySetValue(addDict, kSecAttrApplicationTag, appTagData);  // *** Link to key via the same tag ***
	    if (labelRef) {
	        CFDictionarySetValue(addDict, kSecAttrLabel, labelRef);         // Set the user-visible label
	    } else {
	        // Fallback label if needed, using the tag string directly if possible
	        CFStringRef fallbackLabel = CFStringCreateWithBytes(kCFAllocatorDefault, CFDataGetBytePtr(appTagData), CFDataGetLength(appTagData), kCFStringEncodingUTF8, false);
	        if (fallbackLabel) {
	            CFDictionarySetValue(addDict, kSecAttrLabel, fallbackLabel);
	            CFRelease(fallbackLabel);
	        }
	    }


	    // 3. Add Certificate to Keychain
	    status = SecItemAdd(addDict, NULL); // Result (like the item ref) is not needed here

	    if (status == errSecDuplicateItem) {
	         CLog("importCertificateAndAssociate_internal: Certificate with this tag already exists (errSecDuplicateItem).");
	         // Treat as success if we didn't delete first, or warning otherwise.
	         status = errSecSuccess; // Overwrite status if duplicate is acceptable.
	    } else if (status != errSecSuccess) {
	        CLog("importCertificateAndAssociate_internal: SecItemAdd failed: %d", (int)status);
	    } else {
	        CLog("importCertificateAndAssociate_internal: Certificate added to Keychain successfully.");
	    }


	cleanup:
	    if (certRef) {
	        CFRelease(certRef);
	    }
	     if (labelRef) {
	         CFRelease(labelRef);
	     }
	    if (addDict) {
	        CFRelease(addDict);
	    }
	    CLog("importCertificateAndAssociate_internal: Finished with status: %d", (int)status);
	    return status;
	}

*/
import "C" // CGO import

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
	"unsafe" // Required for CGO calls
)

const (
	caKeyFile  = "ca.key"
	caCertFile = "ca.crt"
	appTag     = "com.example.myapp.seclientkey.v1" // Unique tag for the SE key/cert pair (added version)
)

// --- Go Wrappers for CGO Functions ---

func cgoGenerateSEKeyPair(tag string) ([]byte, error) {
	// Convert Go string tag to CFDataRef for C functions
	tagCStr := C.CString(tag)
	if tagCStr == nil {
		return nil, fmt.Errorf("failed to allocate C string for tag")
	}
	defer C.free(unsafe.Pointer(tagCStr))

	tagData := C.CreateCFData((*C.uchar)(unsafe.Pointer(tagCStr)), C.CFIndex(len(tag)))
	if tagData == 0 {
		return nil, fmt.Errorf("failed to create CFData for tag")
	}
	defer C.CFRelease(C.CFTypeRef(tagData))

	// Call the internal C function
	pubKeyCFData := C.generateSEKeyPair_internal(tagData)
	if pubKeyCFData == 0 {
		return nil, fmt.Errorf("CGO: generateSEKeyPair_internal failed (check Console.app logs for [CGO] messages)")
	}
	// Go now owns pubKeyCFData and must release it
	defer C.CFRelease(C.CFTypeRef(pubKeyCFData))

	// Convert returned CFDataRef to Go byte slice
	length := C.CFDataGetLength(pubKeyCFData)
	ptr := C.CFDataGetBytePtr(pubKeyCFData)
	if ptr == nil {
		// Should not happen if CFDataGetLength > 0, but check anyway
		return nil, fmt.Errorf("CGO: failed to get byte pointer from returned public key CFData")
	}
	publicKeyDer := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	return publicKeyDer, nil
}

func cgoSignWithSEKey(tag string, digest []byte) ([]byte, error) {
	// Convert Go string tag to CFDataRef
	tagCStr := C.CString(tag)
	if tagCStr == nil {
		return nil, fmt.Errorf("failed to allocate C string for tag")
	}
	defer C.free(unsafe.Pointer(tagCStr))
	tagData := C.CreateCFData((*C.uchar)(unsafe.Pointer(tagCStr)), C.CFIndex(len(tag)))
	if tagData == 0 {
		return nil, fmt.Errorf("failed to create CFData for tag")
	}
	defer C.CFRelease(C.CFTypeRef(tagData))

	// Convert Go digest slice to CFDataRef
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest cannot be empty")
	}
	digestCFData := C.CreateCFData((*C.uchar)(&digest[0]), C.CFIndex(len(digest)))
	if digestCFData == 0 {
		return nil, fmt.Errorf("failed to create CFData for digest")
	}
	defer C.CFRelease(C.CFTypeRef(digestCFData))

	// Call the internal C function
	signatureCFData := C.signWithSEKey_internal(tagData, digestCFData)
	if signatureCFData == 0 {
		return nil, fmt.Errorf("CGO: signWithSEKey_internal failed (check Console.app logs for [CGO] messages)")
	}
	// Go now owns signatureCFData and must release it
	defer C.CFRelease(C.CFTypeRef(signatureCFData))

	// Convert returned CFDataRef to Go byte slice
	length := C.CFDataGetLength(signatureCFData)
	ptr := C.CFDataGetBytePtr(signatureCFData)
	if ptr == nil {
		return nil, fmt.Errorf("CGO: failed to get byte pointer from returned signature CFData")
	}
	signatureBytes := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	return signatureBytes, nil
}

func cgoImportCertificateAndAssociate(tag string, certDER []byte) error {
	// Convert Go string tag to CFDataRef
	tagCStr := C.CString(tag)
	if tagCStr == nil {
		return fmt.Errorf("failed to allocate C string for tag")
	}
	defer C.free(unsafe.Pointer(tagCStr))
	tagData := C.CreateCFData((*C.uchar)(unsafe.Pointer(tagCStr)), C.CFIndex(len(tag)))
	if tagData == 0 {
		return fmt.Errorf("failed to create CFData for tag")
	}
	defer C.CFRelease(C.CFTypeRef(tagData))

	// Convert Go cert slice to CFDataRef
	if len(certDER) == 0 {
		return fmt.Errorf("certificate DER cannot be empty")
	}
	certCFData := C.CreateCFData((*C.uchar)(&certDER[0]), C.CFIndex(len(certDER)))
	if certCFData == 0 {
		return fmt.Errorf("failed to create CFData for certificate")
	}
	defer C.CFRelease(C.CFTypeRef(certCFData))

	// Call the internal C function
	status := C.importCertificateAndAssociate_internal(tagData, certCFData)
	if status != C.errSecSuccess {
		// Attempt to get a human-readable error string
		var errStr string
		cfErrStr := C.SecCopyErrorMessageString(status, nil) // Requires Security framework
		if cfErrStr != 0 {
			cErrStr := C.CFStringGetCStringPtr(cfErrStr, C.kCFStringEncodingUTF8)
			if cErrStr != nil {
				errStr = C.GoString(cErrStr)
			} else {
				// Fallback if direct pointer doesn't work
				length := C.CFStringGetLength(cfErrStr)
				maxSize := C.CFStringGetMaximumSizeForEncoding(length, C.kCFStringEncodingUTF8) + 1
				buffer := make([]byte, maxSize)
				// Fix: Convert CFStringGetCString result (Boolean) to Go bool
				result := C.CFStringGetCString(cfErrStr, (*C.char)(unsafe.Pointer(&buffer[0])), C.CFIndex(maxSize), C.kCFStringEncodingUTF8)
				if result != 0 { // 0 is false, non-zero is true
					errStr = string(buffer)
				}
			}
			C.CFRelease(C.CFTypeRef(cfErrStr))
		}
		if errStr == "" {
			errStr = "Unknown Security Error"
		}
		return fmt.Errorf("CGO: importCertificateAndAssociate_internal failed with OSStatus %d (%s) (check Console.app logs)", status, errStr)
	}
	return nil
}

// --- Pure Go Functions (Unchanged from previous example) ---

// createOrLoadCA generates a new CA key/cert or loads existing ones.
func createOrLoadCA() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Check if files exist
	if _, err := os.Stat(caCertFile); err == nil {
		if _, err := os.Stat(caKeyFile); err == nil {
			fmt.Println("Loading existing CA cert and key...")
			// Load existing key
			keyBytes, err := os.ReadFile(caKeyFile)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read CA key file: %w", err)
			}
			keyBlock, _ := pem.Decode(keyBytes)
			if keyBlock == nil {
				return nil, nil, fmt.Errorf("failed to decode CA key PEM")
			}
			caPrivKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
			}

			// Load existing cert
			certBytes, err := os.ReadFile(caCertFile)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read CA cert file: %w", err)
			}
			certBlock, _ := pem.Decode(certBytes)
			if certBlock == nil {
				return nil, nil, fmt.Errorf("failed to decode CA cert PEM")
			}
			caCert, err := x509.ParseCertificate(certBlock.Bytes)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
			}
			fmt.Println("CA loaded successfully.")
			return caCert, caPrivKey, nil
		}
	}

	fmt.Println("Generating new CA key and certificate...")
	// Generate new CA private key
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate CA private key: %w", err)
	}

	// Create CA certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Org CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Create self-signed CA certificate
	caCertBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the created certificate
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse created CA certificate: %w", err)
	}

	// Save CA private key to PEM file
	keyDer, err := x509.MarshalECPrivateKey(caPrivKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal CA private key: %w", err)
	}
	keyFile, err := os.Create(caKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA key file: %w", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA key PEM: %w", err)
	}

	// Save CA certificate to PEM file
	certFile, err := os.Create(caCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CA cert file: %w", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes}); err != nil {
		return nil, nil, fmt.Errorf("failed to write CA cert PEM: %w", err)
	}

	fmt.Println("New CA generated and saved.")
	return caCert, caPrivKey, nil
}

// createCSR generates a CSR using the public key derived from Secure Enclave.
func createCSR(publicKey crypto.PublicKey, signFunc func(digest []byte) ([]byte, error)) ([]byte, error) {
	fmt.Println("Creating CSR template...")
	// Define CSR details
	subj := pkix.Name{
		Organization: []string{"Test Org Client SE"}, // Modified org
		CommonName:   "Test Secure Enclave Client",
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256, // Must match SE signing algorithm
		// DNSNames, EmailAddresses, IPAddresses can be added here if needed
	}

	fmt.Println("Creating CSR base structure...")
	// Generate the To-Be-Signed portion of the CSR
	tbsCSRContents, err := x509.CreateCertificateRequest(rand.Reader, &template, publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create To-Be-Signed CSR data: %w", err)
	}

	// The result of CreateCertificateRequest when privateKey is nil is the marshal'd TBS request data.
	// We need to sign this data.
	digest := sha256.Sum256(tbsCSRContents)

	fmt.Println("Signing CSR digest using Secure Enclave (via CGO)...")
	// Use the provided signing function (which calls CGO)
	// This should return the raw R and S values concatenated.
	rawSignature, err := signFunc(digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign CSR digest via CGO: %w", err)
	}

	// Convert the raw R|S signature to the ASN.1 SEQUENCE { r INTEGER, s INTEGER } format
	ecdsaPubKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA, required for signature parsing")
	}
	curveBits := ecdsaPubKey.Curve.Params().BitSize
	keyBytes := (curveBits + 7) / 8
	if len(rawSignature) != 2*keyBytes {
		// Some implementations might return ASN.1 already. Check for that possibility.
		// Try parsing as ASN.1 first
		var asn1Sig struct{ R, S *big.Int }
		_, err := asn1.Unmarshal(rawSignature, &asn1Sig)
		if err == nil && asn1Sig.R != nil && asn1Sig.S != nil {
			// It was already ASN.1 encoded
			fmt.Println("Note: Signature from CGO was already ASN.1 encoded.")
		} else {
			return nil, fmt.Errorf("unexpected raw signature length from CGO sign: expected %d, got %d (and not ASN.1)", 2*keyBytes, len(rawSignature))
		}
		// If it was ASN.1, use rawSignature directly below
	}

	// If it was raw R|S (and the check above passed)
	var ecdsaSig struct{ R, S *big.Int }
	ecdsaSig.R = new(big.Int).SetBytes(rawSignature[:keyBytes])
	ecdsaSig.S = new(big.Int).SetBytes(rawSignature[keyBytes:])
	asn1Signature, err := asn1.Marshal(ecdsaSig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA signature to ASN.1: %w", err)
	}

	// Assemble the final CSR structure: SEQUENCE { TBSCertificateRequest, SignatureAlgorithm, SignatureValue }
	finalCSR := struct {
		TBSCSR       []byte
		SigAlgorithm pkix.AlgorithmIdentifier
		Signature    asn1.BitString
	}{
		TBSCSR: tbsCSRContents, // The To-Be-Signed data generated earlier
		SigAlgorithm: pkix.AlgorithmIdentifier{ // Must match template/signing algorithm
			Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, // ecdsa-with-SHA256
		},
		Signature: asn1.BitString{Bytes: asn1Signature, BitLength: len(asn1Signature) * 8},
	}

	finalCSRDER, err := asn1.Marshal(finalCSR)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal final CSR structure: %w", err)
	}

	fmt.Println("CSR created and signed.")
	// Save CSR to file for inspection
	csrFile, _ := os.Create("client_se.csr")
	pem.Encode(csrFile, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: finalCSRDER})
	csrFile.Close()
	fmt.Println("CSR saved to client_se.csr")

	return finalCSRDER, nil
}

// signClientCert signs the CSR with the CA.
func signClientCert(csrBytes []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, error) {
	fmt.Println("Parsing CSR...")
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	fmt.Println("Verifying CSR signature...")
	// Verify CSR signature using the *public* key from the CSR.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	fmt.Println("CSR signature verified successfully.")

	// Create client certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number for client cert: %w", err)
	}

	clientTemplate := x509.Certificate{
		// We don't copy Signature/SigAlg from CSR, we generate a new one signed by CA
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm, // Use algorithm from CSR
		PublicKey:          csr.PublicKey,          // Use public key from CSR

		SerialNumber: serialNumber,
		Issuer:       caCert.Subject,                                 // Issuer is the CA
		Subject:      csr.Subject,                                    // Subject taken from CSR
		NotBefore:    time.Now().Add(-1 * time.Minute),               // Allow for slight clock skew
		NotAfter:     time.Now().AddDate(0, 6, 0),                    // 6 months validity
		KeyUsage:     x509.KeyUsageDigitalSignature,                  // Essential for TLS signing
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // *** IMPORTANT for mTLS ***
		// BasicConstraintsValid: false, // Client certs typically aren't CAs
	}

	fmt.Println("Signing client certificate with CA...")
	// Sign the client certificate using the CA's private key and the CSR's public key
	clientCertBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	fmt.Println("Client certificate created.")
	return clientCertBytes, nil
}

// --- Main Function (Modified Error Handling) ---

func main() {
	// === 1. Create or Load CA ===
	caCert, caKey, err := createOrLoadCA()
	if err != nil {
		fmt.Printf("❌ Error with CA: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ CA Loaded/Generated - Subject:", caCert.Subject)

	// === 2. Generate Secure Enclave Key Pair (via CGO) ===
	fmt.Println("⏳ Generating Secure Enclave key pair (via CGO)...")
	publicKeyDer, err := cgoGenerateSEKeyPair(appTag)
	if err != nil {
		fmt.Printf("❌ Error generating SE key pair: %v\n", err)
		fmt.Println("   Check Console.app for '[CGO]' logs from the Security framework.")
		fmt.Println("   Possible issues: Permissions, existing item conflicts, hardware support.")
		os.Exit(1)
	}
	fmt.Println("✅ Secure Enclave public key obtained (DER length):", len(publicKeyDer))

	// Parse the public key
	publicKey, err := x509.ParsePKIXPublicKey(publicKeyDer)
	if err != nil {
		fmt.Printf("❌ Error parsing SE public key DER: %v\n", err)
		os.Exit(1)
	}
	_, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		fmt.Printf("❌ Public key is not ECDSA, type: %T\n", publicKey)
		os.Exit(1)
	}
	fmt.Println("✅ Secure Enclave public key parsed.")

	// === 3. Create and Sign CSR (using SE key via CGO) ===
	fmt.Println("⏳ Creating and signing CSR using Secure Enclave (via CGO)...")
	// Define the signing function closure that uses CGO
	seSigner := func(digest []byte) ([]byte, error) {
		return cgoSignWithSEKey(appTag, digest)
	}
	csrBytes, err := createCSR(publicKey, seSigner)
	if err != nil {
		fmt.Printf("❌ Error creating CSR: %v\n", err)
		fmt.Println("   Check Console.app for '[CGO]' logs. Did key generation succeed? Does key allow signing?")
		os.Exit(1)
	}
	fmt.Println("✅ CSR created and signed using SE key.")

	// === 4. Sign Client Certificate with CA ===
	fmt.Println("⏳ Signing client certificate with CA...")
	clientCertBytes, err := signClientCert(csrBytes, caCert, caKey)
	if err != nil {
		fmt.Printf("❌ Error signing client certificate: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("✅ Client certificate signed by CA.")

	// Optional: Save client cert to file
	clientCertFile, err := os.Create("client_se.crt")
	if err != nil {
		fmt.Printf("⚠️ Warning: failed to create client_se.crt file: %v\n", err)
	} else {
		pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
		clientCertFile.Close()
		fmt.Println("📄 Client certificate saved to client_se.crt")
	}

	// === 5. Import Client Certificate into Keychain (via CGO) ===
	fmt.Println("⏳ Importing client certificate into macOS Keychain (via CGO)...")
	err = cgoImportCertificateAndAssociate(appTag, clientCertBytes)
	if err != nil {
		fmt.Printf("Error importing certificate to Keychain: %v\n", err)
		fmt.Println("NOTE: This likely failed because the CGO import function is a stub.")
		fmt.Println("Check Keychain Access app manually. If the key/cert exist from previous runs, delete them first.")
		os.Exit(1) // Exit because the identity wasn't created
	}

	fmt.Println("\nSuccess! (Conceptual)")
	fmt.Println(" - A Secure Enclave key pair should have been generated (check Keychain Access for a key tagged '" + appTag + "').")
	fmt.Println(" - A client certificate signed by the test CA should have been created.")
	fmt.Println(" - The certificate should be imported into Keychain and associated with the Secure Enclave key, forming an Identity.")
	fmt.Println("\nVerification:")
	fmt.Println(" 1. Open Keychain Access.app.")
	fmt.Println(" 2. Select the 'login' keychain.")
	fmt.Println(" 3. Select 'My Certificates' category.")
	fmt.Println(" 4. Look for a certificate with Common Name 'Test Secure Enclave Client'.")
	fmt.Println(" 5. If found, expand it. It should show a private key underneath.")
	fmt.Println(" 6. Double-click the private key. In the 'Access Control' tab, it *might* indicate usage constraints (depends on CGO implementation detail). Getting info indicating Secure Enclave origin via Keychain Access UI is often difficult.")
	fmt.Println(" 7. Configure a test server for mTLS using ca.crt and try connecting with Chrome. Chrome should prompt you to select the 'Test Secure Enclave Client' certificate.")
}
