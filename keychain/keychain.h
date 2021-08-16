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

void listKeys(void);

void deleteKey(getKeyIn *in, error **err);

void publicKey(SecKeyRef priv, size_t *size, const char **buf, error **err);

void sign(SecKeyRef priv, const void *indata, size_t insize, const char **outdata, size_t *outSize, error **err);
