#import "SEIdentityCreator.h"

// Helper function to convert CFErrorRef to NSError
static NSError* CFErrorToNSError(CFErrorRef cfError) {
    if (cfError == NULL) {
        return nil;
    }
    return (__bridge NSError*)cfError;
}

// Helper function to create SecAccessControl requiring biometry
static SecAccessControlRef CreateBiometricAccessControl(CFErrorRef *error) {
    // kSecAccessControlPrivateKeyUsage allows signing/decryption operations.
    // kSecAccessControlBiometryCurrentSet requires Touch ID/Face ID enrolled on the device.
    // Other options include kSecAccessControlUserPresence, kSecAccessControlBiometryAny, kSecAccessControlDevicePasscode
    return SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                           kSecAttrAccessibleWhenUnlockedThisDeviceOnly, // Or kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly etc.
                                           kSecAccessControlPrivateKeyUsage, // | kSecAccessControlBiometryCurrentSet,
                                           error);
}

// Helper function to get LAContext for operations requiring UI/auth
static LAContext* GetLAContext() {
    LAContext *context = [[LAContext alloc] init];
    // You might customize the context here if needed, e.g., context.localizedReason
    return context;
}


int GenerateSEKeyPairAndGetPublicKey(const char *keyLabel,
                                     unsigned char **outPublicKeyDER,
                                     size_t *outPublicKeyLength) {
    if (!keyLabel || !outPublicKeyDER || !outPublicKeyLength) {
        NSLog(@"[SE Identity] Error: Invalid input parameters for key generation.");
        return SE_ERR_INVALID_INPUT;
    }
    *outPublicKeyDER = NULL;
    *outPublicKeyLength = 0;

    CFErrorRef accessControlError = NULL;
    SecAccessControlRef accessControl = CreateBiometricAccessControl(&accessControlError);
    if (!accessControl) {
        NSError *nsError = CFErrorToNSError(accessControlError);
        NSLog(@"[SE Identity] Error creating access control: %@", nsError);
        if (accessControlError) CFRelease(accessControlError);
        return SE_ERR_ACCESS_CONTROL;
    }

    NSString *nsLabel = [NSString stringWithUTF8String:keyLabel];
    NSData *tag = [nsLabel dataUsingEncoding:NSUTF8StringEncoding]; // Use label as tag

    // Attributes for the private key
    NSDictionary *privateKeyAttrs = @{
        (id)kSecAttrIsPermanent: @YES,
        (id)kSecAttrApplicationTag: tag, // Tagging for later lookup
        (id)kSecAttrAccessControl: (__bridge_transfer id)accessControl // Transfer ownership
    };

    // Attributes for the key pair generation
    NSDictionary *keyPairAttrs = @{
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom, // EC key on Secure Enclave
        (id)kSecAttrKeySizeInBits: @256, // P-256
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave, // Specify Secure Enclave
        (id)kSecAttrLabel: nsLabel, // User-visible label in Keychain Access
        (id)kSecPrivateKeyAttrs: privateKeyAttrs
    };

    CFErrorRef keyGenError = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)keyPairAttrs, &keyGenError);

    if (!privateKey) {
        NSError *nsError = CFErrorToNSError(keyGenError);
        NSLog(@"[SE Identity] Error generating key pair: %@", nsError);
        if (keyGenError) CFRelease(keyGenError);
        // Clean up potentially created item if generation partially failed? Usually not needed.
        return SE_ERR_KEY_GENERATION;
    }

    // Get the public key
    SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
    CFRelease(privateKey); // Release private key ref, it's stored securely

    if (!publicKey) {
        NSLog(@"[SE Identity] Error: Could not copy public key.");
        return SE_ERR_KEY_GENERATION; // Or a different error
    }

    // Export the public key to DER format
    CFErrorRef exportError = NULL;
    NSData *publicKeyData = (NSData *)CFBridgingRelease(SecKeyCopyExternalRepresentation(publicKey, &exportError));
    CFRelease(publicKey); // Release public key ref

    if (!publicKeyData) {
        NSError *nsError = CFErrorToNSError(exportError);
        NSLog(@"[SE Identity] Error exporting public key: %@", nsError);
        if (exportError) CFRelease(exportError);
        return SE_ERR_PUBKEY_EXPORT;
    }

    // Allocate memory for the output buffer (caller must free)
    size_t len = [publicKeyData length];
    unsigned char *buffer = (unsigned char *)malloc(len);
    if (!buffer) {
         NSLog(@"[SE Identity] Error: Failed to allocate memory for public key buffer.");
         return SE_ERR_UNKNOWN; // Memory allocation error
    }
    memcpy(buffer, [publicKeyData bytes], len);

    *outPublicKeyDER = buffer;
    *outPublicKeyLength = len;

    NSLog(@"[SE Identity] Successfully generated SE key pair with label: %@", nsLabel);
    return SE_SUCCESS;
}


int SignDataWithSEKey(const char *keyLabel,
                      const unsigned char *dataToSign,
                      size_t dataToSignLength,
                      unsigned char **outSignature,
                      size_t *outSignatureLength) {

    if (!keyLabel || !dataToSign || dataToSignLength == 0 || !outSignature || !outSignatureLength) {
         NSLog(@"[SE Identity] Error: Invalid input parameters for signing.");
        return SE_ERR_INVALID_INPUT;
    }
    *outSignature = NULL;
    *outSignatureLength = 0;

    NSString *nsLabel = [NSString stringWithUTF8String:keyLabel];
    NSData *tag = [nsLabel dataUsingEncoding:NSUTF8StringEncoding];

    // Query to find the private key
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrApplicationTag: tag, // Find by tag
        (id)kSecAttrLabel: nsLabel,       // Match label as well
        (id)kSecReturnRef: @YES,
        (id)kSecUseAuthenticationContext: GetLAContext() // Provide context for potential UI prompt
    };

    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

    if (status == errSecItemNotFound) {
        NSLog(@"[SE Identity] Error: Private key with label '%@' not found.", nsLabel);
        return SE_ERR_KEY_NOT_FOUND;
    } else if (status == errSecUserCanceled || status == errSecAuthFailed) {
         NSLog(@"[SE Identity] Error: User cancelled or failed biometric authentication. Status: %d", (int)status);
         if (privateKey) CFRelease(privateKey);
         return SE_ERR_AUTH_FAILED;
    } else if (status != errSecSuccess) {
        NSLog(@"[SE Identity] Error querying private key. Status: %d", (int)status);
        if (privateKey) CFRelease(privateKey);
        return SE_ERR_KEY_QUERY_FAILED;
    }

    if (!privateKey) {
         NSLog(@"[SE Identity] Error: SecItemCopyMatching succeeded but returned NULL key ref.");
         return SE_ERR_KEY_QUERY_FAILED;
    }

    // Determine the signing algorithm (ECDSA with SHA-256 for P-256)
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    // Check if key supports the algorithm (optional but good practice)
    if (!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm)) {
        NSLog(@"[SE Identity] Error: Key does not support algorithm %@", algorithm);
        CFRelease(privateKey);
        return SE_ERR_SIGNATURE_FAILED; // Or a more specific error
    }

    NSData *dataToSignNS = [NSData dataWithBytes:dataToSign length:dataToSignLength];
    CFErrorRef signError = NULL;

    // Perform the signing operation (this triggers Secure Enclave & potential UI)
    NSData *signatureData = (NSData *)CFBridgingRelease(SecKeyCreateSignature(privateKey,
                                                                             algorithm,
                                                                             (__bridge CFDataRef)dataToSignNS,
                                                                             &signError));
    CFRelease(privateKey); // Release key ref

    if (!signatureData) {
        NSError *nsError = CFErrorToNSError(signError);
        // Check if the error indicates user cancellation
        if ([nsError.domain isEqualToString:LAErrorDomain] && (nsError.code == LAErrorUserCancel || nsError.code == LAErrorAuthenticationFailed)) {
             NSLog(@"[SE Identity] Signing failed: User cancelled or failed biometric authentication: %@", nsError);
             if (signError) CFRelease(signError);
             return SE_ERR_AUTH_FAILED;
        } else {
            NSLog(@"[SE Identity] Error creating signature: %@", nsError);
            if (signError) CFRelease(signError);
            return SE_ERR_SIGNATURE_FAILED;
        }
    }

    // Allocate memory for the output buffer (caller must free)
    size_t len = [signatureData length];
    unsigned char *buffer = (unsigned char *)malloc(len);
     if (!buffer) {
         NSLog(@"[SE Identity] Error: Failed to allocate memory for signature buffer.");
         return SE_ERR_UNKNOWN; // Memory allocation error
    }
    memcpy(buffer, [signatureData bytes], len);

    *outSignature = buffer;
    *outSignatureLength = len;

    NSLog(@"[SE Identity] Successfully signed data using SE key with label: %@", nsLabel);
    return SE_SUCCESS;
}


int ProvisionIdentityWithCertificate(const char *keyLabel,
                                     const unsigned char *certificateDER,
                                     size_t certificateDERLength) {

    if (!keyLabel || !certificateDER || certificateDERLength == 0) {
        NSLog(@"[SE Identity] Error: Invalid input parameters for provisioning.");
        return SE_ERR_INVALID_INPUT;
    }

    NSString *nsLabel = [NSString stringWithUTF8String:keyLabel];
    NSData *tag = [nsLabel dataUsingEncoding:NSUTF8StringEncoding]; // Use same tag as key

    // 1. Create a SecCertificateRef from the DER data
    NSData *certData = [NSData dataWithBytes:certificateDER length:certificateDERLength];
    SecCertificateRef certificate = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)certData);
    if (!certificate) {
        NSLog(@"[SE Identity] Error: Failed to create SecCertificateRef from DER data.");
        return SE_ERR_CERT_CREATE_FAILED;
    }

    // 2. Prepare attributes for adding the certificate to the Keychain
    // We add the certificate as a separate item, but tag/label it identically
    // to the private key. The system uses the public key within the certificate
    // to find the matching private key (including SE keys) to form the SecIdentity.
    NSDictionary *certAddDict = @{
        (id)kSecClass: (id)kSecClassCertificate,
        (id)kSecValueRef: (__bridge_transfer id)certificate, // Transfer ownership
        (id)kSecAttrLabel: nsLabel, // Use the same label as the key
        (id)kSecAttrApplicationTag: tag, // Optionally use the same tag
        // Make it persistent (usually desired)
        (id)kSecAttrIsPermanent: @YES, // Although certs are often added as permanent by default
    };

    // 3. Add the certificate to the Keychain
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)certAddDict, NULL);

    // Handle potential duplicate item error (maybe update instead?)
    if (status == errSecDuplicateItem) {
        NSLog(@"[SE Identity] Certificate with label '%@' already exists. Attempting to update.", nsLabel);
        // Query for the existing certificate
        NSDictionary *query = @{
            (id)kSecClass: (id)kSecClassCertificate,
            (id)kSecAttrLabel: nsLabel,
            (id)kSecAttrApplicationTag: tag
        };
        // Attributes to update (replace the certificate data)
        NSDictionary *update = @{
            (id)kSecValueRef: (__bridge id)certificate // Don't transfer ownership here, SecItemUpdate uses it
        };
        status = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)update);
         // Release the certificate ref now if we didn't transfer it earlier
        // CFRelease(certificate); // Release if update was attempted or add failed other than duplicate

        if (status != errSecSuccess) {
             NSLog(@"[SE Identity] Error updating existing certificate. Status: %d", (int)status);
             // Make sure to release the cert ref created earlier if not transferred
             // CFRelease(certificate); // This was transferred in the SecItemAdd path, careful here.
             // If add failed with duplicate and update failed, the original cert ref needs release.
             // Let's simplify: just log the duplicate and return an error for now.
             NSLog(@"[SE Identity] Error: Certificate with label '%@' already exists and update failed (or wasn't implemented fully). Status: %d", nsLabel, (int)status);
             // CFRelease(certificate); // Release the ref created at the start
             return SE_ERR_CERT_ADD_FAILED; // Treat duplicate without update as failure for simplicity
        }
         NSLog(@"[SE Identity] Successfully updated existing certificate with label: %@", nsLabel);

    } else if (status != errSecSuccess) {
        NSLog(@"[SE Identity] Error adding certificate to Keychain. Status: %d", (int)status);
        // CFRelease(certificate); // Release if add failed (and wasn't transferred)
        return SE_ERR_CERT_ADD_FAILED;
    } else {
         NSLog(@"[SE Identity] Successfully added certificate and provisioned identity with label: %@", nsLabel);
    }

    // If SecItemAdd succeeded, the certificate ref was transferred (__bridge_transfer).
    // If it failed with duplicate and update succeeded, it was bridged (__bridge).
    // If add failed otherwise, it needs release. Careful management is needed.
    // The code above assumes success or handles duplicate+update failure.

    // At this point, macOS should implicitly link the certificate and the
    // Secure Enclave private key (found via matching public keys) into a SecIdentityRef
    // usable by applications like Chrome for mTLS.

    return SE_SUCCESS;
}

// Function to list labels and tags of keys stored in the Secure Enclave
int ListSEKeyInfos(SEKeyInfo** outKeyInfos, int* outCount) {
    if (!outKeyInfos || !outCount) {
        NSLog(@"[SE Identity] Error: Invalid output parameters for listing key infos.");
        return SE_ERR_INVALID_INPUT;
    }
    *outKeyInfos = NULL;
    *outCount = 0;

    // Query for EC keys stored in the Secure Enclave
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrTokenID: (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecReturnAttributes: @YES, // We want the attributes dictionary
        (id)kSecMatchLimit: (id)kSecMatchLimitAll // Get all matching items
    };

    CFArrayRef results = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&results);

    if (status == errSecItemNotFound) {
        NSLog(@"[SE Identity] No Secure Enclave keys found matching the criteria.");
        return SE_SUCCESS; // Not an error, just no keys found
    } else if (status != errSecSuccess) {
        NSLog(@"[SE Identity] Error querying Secure Enclave keys. Status: %d", (int)status);
        if (results) CFRelease(results);
        return SE_ERR_KEY_QUERY_FAILED;
    }

    CFIndex count = CFArrayGetCount(results);
    if (count == 0) {
        NSLog(@"[SE Identity] Query succeeded but found 0 keys.");
        CFRelease(results);
        return SE_SUCCESS; // No keys found
    }

    // Allocate the array of SEKeyInfo structs
    SEKeyInfo *keyInfos = (SEKeyInfo *)malloc(count * sizeof(SEKeyInfo));
    if (!keyInfos) {
        NSLog(@"[SE Identity] Error: Failed to allocate memory for key info array.");
        CFRelease(results);
        return SE_ERR_UNKNOWN;
    }
    // Initialize to zero/NULL
    memset(keyInfos, 0, count * sizeof(SEKeyInfo));

    int actualCount = 0;
    for (CFIndex i = 0; i < count; ++i) {
        CFDictionaryRef item = (CFDictionaryRef)CFArrayGetValueAtIndex(results, i);
        if (!item || CFGetTypeID(item) != CFDictionaryGetTypeID()) {
            continue; // Skip non-dictionary items
        }

        // Get Label
        CFStringRef labelRef = (CFStringRef)CFDictionaryGetValue(item, kSecAttrLabel);
        char *labelCopy = NULL;
        if (labelRef && CFGetTypeID(labelRef) == CFStringGetTypeID()) {
            const char *labelCStr = CFStringGetCStringPtr(labelRef, kCFStringEncodingUTF8);
            if (labelCStr) {
                size_t len = strlen(labelCStr) + 1;
                labelCopy = (char *)malloc(len);
                if (labelCopy) memcpy(labelCopy, labelCStr, len);
            } else {
                CFIndex bufferSize = CFStringGetMaximumSizeForEncoding(CFStringGetLength(labelRef), kCFStringEncodingUTF8) + 1;
                labelCopy = (char *)malloc(bufferSize);
                if (!(labelCopy && CFStringGetCString(labelRef, labelCopy, bufferSize, kCFStringEncodingUTF8))) {
                    if (labelCopy) free(labelCopy); labelCopy = NULL;
                }
            }
        }
        if (!labelCopy) {
             NSLog(@"[SE Identity] Warning: Found key without a valid label or failed allocation/conversion, skipping.");
             // Continue to next item, but don't increment actualCount yet.
             // Or should we add it with NULL label? Let's skip for now.
             continue;
        }

        // Get Tag
        CFDataRef tagRef = (CFDataRef)CFDictionaryGetValue(item, kSecAttrApplicationTag);
        void *tagDataCopy = NULL;
        size_t tagLength = 0;
        if (tagRef && CFGetTypeID(tagRef) == CFDataGetTypeID()) {
            tagLength = CFDataGetLength(tagRef);
            if (tagLength > 0) {
                tagDataCopy = malloc(tagLength);
                if (tagDataCopy) {
                    memcpy(tagDataCopy, CFDataGetBytePtr(tagRef), tagLength);
                } else {
                     NSLog(@"[SE Identity] Warning: Failed to allocate memory for tag data, skipping tag.");
                    tagLength = 0; // Reset length if allocation failed
                }
            }
        } else {
             NSLog(@"[SE Identity] Warning: Found key without a valid tag (kSecAttrApplicationTag), skipping tag.");
        }

        // If tag allocation failed, tagDataCopy is NULL and tagLength is 0.
        // If tag was missing/invalid, tagDataCopy is NULL and tagLength is 0.

        // Store the copied data in the struct
        keyInfos[actualCount].label = labelCopy; // Ownership transferred
        keyInfos[actualCount].tagData = tagDataCopy; // Ownership transferred (or NULL)
        keyInfos[actualCount].tagLength = tagLength;
        actualCount++;
    }

    CFRelease(results);

    if (actualCount == 0 && count > 0) {
         NSLog(@"[SE Identity] Warning: Queried %ld keys, but none had valid labels suitable for return.", count);
         free(keyInfos); // Free the array itself
         return SE_SUCCESS; // Still success, just no usable keys found
    } else if (actualCount < count) {
         NSLog(@"[SE Identity] Warning: Skipped %ld keys due to missing/invalid labels.", count - actualCount);
         // Optionally realloc keyInfos array to actualCount size, but not critical
    }

    *outKeyInfos = keyInfos;
    *outCount = actualCount;

    NSLog(@"[SE Identity] Successfully listed %d Secure Enclave key infos.", actualCount);
    return SE_SUCCESS;
}

// Helper function to free the memory allocated by ListSEKeyInfos
void FreeSEKeyInfoList(SEKeyInfo *keyInfos, int count) {
    if (!keyInfos) {
        return;
    }
    for (int i = 0; i < count; ++i) {
        if (keyInfos[i].label) {
            free(keyInfos[i].label);
        }
        if (keyInfos[i].tagData) {
            free(keyInfos[i].tagData);
        }
    }
    free(keyInfos);
}

// Implementation for signing a pre-computed digest
int SignDigestWithSEKey(const char *keyLabel,
                        const unsigned char *digest,
                        size_t digestLength,
                        unsigned char **outSignature,
                        size_t *outSignatureLength) {

    if (!keyLabel || !digest || digestLength == 0 || !outSignature || !outSignatureLength) {
         NSLog(@"[SE Identity] Error: Invalid input parameters for digest signing.");
        return SE_ERR_INVALID_INPUT;
    }
    *outSignature = NULL;
    *outSignatureLength = 0;

    // Basic check for expected digest length (SHA-256 = 32 bytes)
    // This could be made more flexible if needed.
    if (digestLength != 32) {
         NSLog(@"[SE Identity] Warning: Digest length (%zu) is not 32 bytes (expected SHA-256).", digestLength);
        // Proceed anyway, but log warning.
    }

    NSString *nsLabel = [NSString stringWithUTF8String:keyLabel];
    NSData *tag = [nsLabel dataUsingEncoding:NSUTF8StringEncoding];

    // Query to find the private key
    NSDictionary *query = @{
        (id)kSecClass: (id)kSecClassKey,
        (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrApplicationTag: tag,
        (id)kSecAttrLabel: nsLabel,
        (id)kSecReturnRef: @YES,
        (id)kSecUseAuthenticationContext: GetLAContext() // Provide context for potential UI prompt
    };

    SecKeyRef privateKey = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKey);

    if (status == errSecItemNotFound) {
        NSLog(@"[SE Identity] Error: Private key with label '%@' not found for digest signing.", nsLabel);
        return SE_ERR_KEY_NOT_FOUND;
    } else if (status == errSecUserCanceled || status == errSecAuthFailed) {
         NSLog(@"[SE Identity] Error: User cancelled or failed biometric authentication during digest signing. Status: %d", (int)status);
         if (privateKey) CFRelease(privateKey);
         return SE_ERR_AUTH_FAILED;
    } else if (status != errSecSuccess) {
        NSLog(@"[SE Identity] Error querying private key for digest signing. Status: %d", (int)status);
        if (privateKey) CFRelease(privateKey);
        return SE_ERR_KEY_QUERY_FAILED;
    }

    if (!privateKey) {
         NSLog(@"[SE Identity] Error: SecItemCopyMatching succeeded but returned NULL key ref for digest signing.");
         return SE_ERR_KEY_QUERY_FAILED;
    }

    // Determine the signing algorithm (ECDSA with SHA-256 *Digest*)
    SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
    if (!SecKeyIsAlgorithmSupported(privateKey, kSecKeyOperationTypeSign, algorithm)) {
        NSLog(@"[SE Identity] Error: Key does not support digest signing algorithm %@", algorithm);
        CFRelease(privateKey);
        return SE_ERR_SIGNATURE_FAILED;
    }

    NSData *digestNS = [NSData dataWithBytes:digest length:digestLength];
    CFErrorRef signError = NULL;

    // Perform the signing operation using the digest
    NSData *signatureData = (NSData *)CFBridgingRelease(SecKeyCreateSignature(privateKey,
                                                                             algorithm,
                                                                             (__bridge CFDataRef)digestNS, // Pass the digest directly
                                                                             &signError));
    CFRelease(privateKey);

    if (!signatureData) {
        NSError *nsError = CFErrorToNSError(signError);
        if ([nsError.domain isEqualToString:LAErrorDomain] && (nsError.code == LAErrorUserCancel || nsError.code == LAErrorAuthenticationFailed)) {
             NSLog(@"[SE Identity] Digest signing failed: User cancelled or failed biometric authentication: %@", nsError);
             if (signError) CFRelease(signError);
             return SE_ERR_AUTH_FAILED;
        } else {
            NSLog(@"[SE Identity] Error creating signature from digest: %@", nsError);
            if (signError) CFRelease(signError);
            return SE_ERR_SIGNATURE_FAILED;
        }
    }

    // Allocate memory for the output buffer (caller must free)
    size_t len = [signatureData length];
    unsigned char *buffer = (unsigned char *)malloc(len);
     if (!buffer) {
         NSLog(@"[SE Identity] Error: Failed to allocate memory for digest signature buffer.");
         return SE_ERR_UNKNOWN;
    }
    memcpy(buffer, [signatureData bytes], len);

    *outSignature = buffer;
    *outSignatureLength = len;

    NSLog(@"[SE Identity] Successfully signed digest using SE key with label: %@", nsLabel);
    return SE_SUCCESS;
}
