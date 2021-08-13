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
        NSError *nerr = CFBridgingRelease(createErr);  // ARC takes ownership
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
    NSDictionary *getquery = @{ (id)kSecClass: (id)kSecClassKey,
                            (id)kSecAttrApplicationTag: [[NSString stringWithUTF8String:in->tag] dataUsingEncoding:NSUTF8StringEncoding],
                            (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
                            (id)kSecReturnRef: @YES,
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
    else {
        getKeyOut *o = malloc(sizeof(*out));
        o->privateKey = key;
        *out = o;
     }
}
