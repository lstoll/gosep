#ifndef SEIdentityCreator_h
#define SEIdentityCreator_h

#include <stddef.h> // Include for size_t definition

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <LocalAuthentication/LocalAuthentication.h> // For LAContext

#ifdef __cplusplus
extern "C" {
#endif

// Error codes
#define SE_SUCCESS 0
#define SE_ERR_ACCESS_CONTROL -1
#define SE_ERR_KEY_GENERATION -2
#define SE_ERR_KEY_QUERY_FAILED -3
#define SE_ERR_KEY_NOT_FOUND -4
#define SE_ERR_PUBKEY_EXPORT -5
#define SE_ERR_SIGNATURE_FAILED -6
#define SE_ERR_CERT_CREATE_FAILED -7
#define SE_ERR_CERT_ADD_FAILED -8
#define SE_ERR_INVALID_INPUT -9
#define SE_ERR_AUTH_FAILED -10 // User failed/cancelled biometric auth
#define SE_ERR_UNKNOWN -99

/**
 * Generates a new EC P-256 key pair within the Secure Enclave.
 * The private key requires biometric authentication (Touch ID/Face ID) for use.
 *
 * @param keyLabel A unique label (C string) to identify this key pair in the Keychain.
 * @param outPublicKeyDER A pointer to a buffer where the DER-encoded public key will be written.
 * The caller must free this buffer using free().
 * @param outPublicKeyLength A pointer to store the length of the public key DER data.
 * @return SE_SUCCESS on success, or a negative SE_ERR_* code on failure.
 */
int GenerateSEKeyPairAndGetPublicKey(const char *keyLabel,
                                     unsigned char **outPublicKeyDER,
                                     size_t *outPublicKeyLength);

/**
 * Signs the provided data using the Secure Enclave private key identified by keyLabel.
 * This operation will likely trigger a biometric prompt for the user.
 *
 * @param keyLabel The label (C string) of the private key to use for signing.
 * @param dataToSign A buffer containing the data to be signed.
 * @param dataToSignLength The length of the data in dataToSign.
 * @param outSignature A pointer to a buffer where the signature data (ASN.1 encoded for ECDSA) will be written.
 * The caller must free this buffer using free().
 * @param outSignatureLength A pointer to store the length of the signature data.
 * @return SE_SUCCESS on success, or a negative SE_ERR_* code on failure (e.g., key not found, user cancellation).
 */
int SignDataWithSEKey(const char *keyLabel,
                      const unsigned char *dataToSign,
                      size_t dataToSignLength,
                      unsigned char **outSignature,
                      size_t *outSignatureLength);


/**
 * Imports a DER-encoded certificate into the Keychain and associates it with the
 * Secure Enclave private key identified by keyLabel, creating a SecIdentity.
 *
 * @param keyLabel The label (C string) of the private key to associate the certificate with.
 * @param certificateDER A buffer containing the DER-encoded certificate.
 * @param certificateDERLength The length of the certificate data.
 * @return SE_SUCCESS on success, or a negative SE_ERR_* code on failure.
 */
int ProvisionIdentityWithCertificate(const char *keyLabel,
                                     const unsigned char *certificateDER,
                                     size_t certificateDERLength);

// Struct to hold information about a listed key
typedef struct {
    char* label;    // The key's label (kSecAttrLabel). Caller must free this.
    void* tagData;  // Pointer to the key's tag data (kSecAttrApplicationTag). Caller must free this.
    size_t tagLength; // Length of the tag data.
} SEKeyInfo;

// Struct to hold information about a Keychain Identity
typedef struct {
    char* label; // Typically the Common Name from the certificate (caller must free)
    // Add other fields if needed, e.g., persistent ref, issuer, etc.
} KeychainIdentityInfo;

/**
 * Lists the labels and tags of all EC P-256 keys stored in the Secure Enclave
 * matching the query criteria.
 *
 * @param outKeyInfos A pointer to receive a dynamically allocated array of SEKeyInfo structs.
 * Both the array itself and the 'label' and 'tagData' fields within each struct
 * are dynamically allocated.
 * The caller is responsible for freeing this memory using FreeSEKeyInfoList().
 * On failure or if no keys are found, *outKeyInfos will be set to NULL.
 * @param outCount A pointer to store the number of key infos returned in outKeyInfos.
 * @return SE_SUCCESS on success (even if no keys are found), or a negative SE_ERR_* code on failure.
 */
int ListSEKeyInfos(SEKeyInfo** outKeyInfos, int* outCount);

/**
 * Frees the memory allocated by ListSEKeyInfos.
 *
 * @param keyInfos The array of SEKeyInfo structs returned by ListSEKeyInfos.
 * @param count The number of structs in the array, as returned by ListSEKeyInfos.
 */
void FreeSEKeyInfoList(SEKeyInfo *keyInfos, int count);

// Sign a pre-computed digest using the SE key associated with the label.
// The digest is expected to be SHA-256 for use with P-256 keys here.
// Caller MUST free the returned outSignature buffer using free().
int SignDigestWithSEKey(const char *keyLabel,
                        const unsigned char *digest,
                        size_t digestLength,
                        unsigned char **outSignature,
                        size_t *outSignatureLength);

// Lists information (currently just the label/CN) about Keychain identities available to the app.
// `outIdentityInfos`: Pointer to receive an allocated array of KeychainIdentityInfo structs. Caller must free this array and its contents using FreeKeychainIdentityInfoList.
// `outCount`: Pointer to receive the number of identities found.
// Returns SE_SUCCESS on success, or an error code otherwise.
int ListKeychainIdentities(KeychainIdentityInfo** outIdentityInfos, int* outCount);

// Frees the memory allocated by ListKeychainIdentities.
// `identityInfos`: The array allocated by ListKeychainIdentities.
// `count`: The number of elements in the array.
void FreeKeychainIdentityInfoList(KeychainIdentityInfo *identityInfos, int count);

#ifdef __cplusplus
} // extern "C"
#endif

#endif /* SEIdentityCreator_h */
