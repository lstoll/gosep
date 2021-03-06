#import <Foundation/Foundation.h>
#import "keychain.h"

void createKey(createKeyIn *in, createKeyOut **out, error **err) {
    SecAccessControlRef access =
        SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                        in->protection,
                                        kSecAccessControlPrivateKeyUsage,
                                        NULL);   // Ignore error

    NSData* tag = [[NSString stringWithUTF8String:in->tag] dataUsingEncoding:NSUTF8StringEncoding];

    NSDictionary* attributes =
    @{ (id)kSecAttrKeyType:             (id)kSecAttrKeyTypeECSECPrimeRandom,
        (id)kSecAttrKeySizeInBits:       @256,
        (id)kSecAttrTokenID:             (id)kSecAttrTokenIDSecureEnclave,
        (id)kSecPrivateKeyAttrs:
        @{ (id)kSecAttrIsPermanent:    @YES,
            (id)kSecAttrApplicationTag: tag,
            (id)kSecAttrAccessControl:  (__bridge id)access,
            },
    };

    CFErrorRef createErr = NULL;
    SecKeyRef privateKey = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes,
                                             &createErr);
    if (!privateKey) {
        NSError *nerr = CFBridgingRelease(createErr);
        error *e = malloc(sizeof(*err));
        e->message = [[nerr localizedDescription] UTF8String];
        e->code = (int) [nerr code];
        *err = e;
        return;
    }

    createKeyOut *o = malloc(sizeof(*out));
    o->privateKey = privateKey;
    *out = o;
}

void getKey(getKeyIn *in, getKeyOut **out, error **err) {
    NSDictionary *getquery = @{ (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrApplicationTag: [[NSString stringWithUTF8String:in->tag] dataUsingEncoding:NSUTF8StringEncoding],
                            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
                            (__bridge id)kSecReturnRef: @YES,
                         };

    SecKeyRef key = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)getquery,
                                      (CFTypeRef *)&key);
    if (status!=errSecSuccess) {
        NSError *nerr = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        error *e = malloc(sizeof(*err));
        e->code = (int)status;
        e->message = [[nerr localizedDescription] UTF8String];
        *err = e;
        return;
    }

    getKeyOut *o = malloc(sizeof(*out));
    o->privateKey = key;
    *out = o;
}

void listKeys(void) {
    // TODO - what would a list function actually look like, and what would be
    // the best data type to return?
    NSDictionary *query = @{ (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecReturnAttributes: @YES,
                            (__bridge id)kSecMatchLimit: (__bridge id)kSecMatchLimitAll,
                            (__bridge id)kSecAttrApplicationTag: [@"li.lds.gosep.testkey1" dataUsingEncoding:NSUTF8StringEncoding],
                            // (__bridge id)kSecAttrApplicationLabel: [@"MZXW569JYG.li.lds.keychain-basic" dataUsingEncoding:NSUTF8StringEncoding],
                        };

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    if (status == errSecSuccess) {
        printf("[SecItemCopyMatching] Success\n");

        NSArray *ary = (__bridge_transfer NSArray *)result;
        printf("Search result: %ld\n", [ary count]);
        for (NSDictionary *item in ary) {
            NSLog(@"%@", item);
        }
        // CFRelease(result);

    } else if (status == errSecItemNotFound) {
        printf("[SecItemCopyMatching] NotFound\n");
    } else {
        printf("[SecItemCopyMatching] error: %d\n", status);
    }
}

void deleteKey(getKeyIn *in, error **err) {
    NSDictionary *query = @{ (__bridge id)kSecClass: (__bridge id)kSecClassKey,
                            (__bridge id)kSecAttrApplicationTag: [[NSString stringWithUTF8String:in->tag] dataUsingEncoding:NSUTF8StringEncoding],
                            (__bridge id)kSecAttrKeyType: (__bridge id)kSecAttrKeyTypeECSECPrimeRandom,
                            (__bridge id)kSecReturnRef: @YES,
                         };


    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)query);
     if (status!=errSecSuccess) {
        NSError *nerr = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
        error *e = malloc(sizeof(*err));
        e->code = (int)status;
        e->message = [[nerr localizedDescription] UTF8String];
        *err = e;
        return;
    }
}

void publicKey(SecKeyRef priv, size_t *size, const char **buf, error **err) {
    SecKeyRef publicKey = SecKeyCopyPublicKey(priv);

    CFErrorRef cfError = NULL;
    NSData* keyData = (NSData*)CFBridgingRelease(  // ARC takes ownership
                        SecKeyCopyExternalRepresentation(publicKey, &cfError)
                   );
    if (!keyData) {
        NSError *nerr = CFBridgingRelease(cfError);  // ARC takes ownership
        error *e = malloc(sizeof(*err));
        e->message = [[nerr localizedDescription] UTF8String];
        e->code = (int) [nerr code];
        *err = e;
        return;
    }

    NSUInteger len = [keyData length];
    void *b = malloc(len);
    memcpy(b, [keyData bytes], len);
    *buf = b;
    *size = len;
}

void sign(SecKeyRef priv, const void *indata, size_t insize, const char **outdata, size_t *outSize, error **err) {
    NSData* data = [NSData dataWithBytes:indata length:insize];

    // TODO check:
    // BOOL canSign = SecKeyIsAlgorithmSupported(privateKey,
    //                                      kSecKeyOperationTypeSign,
    //

    CFErrorRef cfError = NULL;
    NSData *signature = (NSData*)CFBridgingRelease(       // ARC takes ownership
                     SecKeyCreateSignature(priv,
                                            kSecKeyAlgorithmECDSASignatureDigestX962SHA256,
                                           (__bridge CFDataRef)data,
                                           &cfError));
    if (!signature) {
        NSError *nerr = CFBridgingRelease(cfError);  // ARC takes ownership
        error *e = malloc(sizeof(*err));
        e->message = [[nerr localizedDescription] UTF8String];
        e->code = (int) [nerr code];
        *err = e;
        return;
    }

    NSUInteger len = [signature length];
    void *b = malloc(len);
    memcpy(b, [signature bytes], len);
    *outdata = b;
    *outSize = len;
}
