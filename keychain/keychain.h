#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

typedef struct {
    const char *message;
} error;

typedef struct {
    const char *tag;
    CFStringRef protection;
} createKeyIn;

typedef struct {
    SecKeyRef privateKey;
} createKeyOut;

void createKey(createKeyIn *in, createKeyOut **out, error **err);
