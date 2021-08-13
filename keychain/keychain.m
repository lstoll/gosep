#import <Foundation/Foundation.h>
#import "keychain.h"

void testFunction(testIn *in, testOut **out) {
    NSString *nss = [NSString stringWithUTF8String:in->inmessage];
    NSLog(@"%@", nss);

    testOut *o = malloc(sizeof(*out));
    o->outmessage = "something to send back";
    *out = o;
}
