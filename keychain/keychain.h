
typedef struct {
    const char *inmessage;
} testIn;

typedef struct {
    const char *outmessage;
} testOut;

void testFunction(testIn *in, testOut **out);
