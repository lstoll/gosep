#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

typedef struct {
    const char *message;
    int code;
} error;

typedef struct {
    const char *tag;
    CFStringRef protection;
} createKeyIn;

typedef struct {
    SecKeyRef privateKey;
} createKeyOut;

void createKey(createKeyIn *in, createKeyOut **out, error **err);

typedef struct {
    const char *tag;
} getKeyIn;

typedef struct {
    SecKeyRef privateKey;
} getKeyOut;

void getKey(getKeyIn *in, getKeyOut **out, error **err);
