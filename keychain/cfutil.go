package keychain

// #cgo CFLAGS: -mmacosx-version-min=10.13
// #cgo LDFLAGS: -framework CoreFoundation
// #import <CoreFoundation/CoreFoundation.h>
import "C"

import (
	"fmt"
	"math"
	"unsafe"
)

func mapToCFDictionary(m map[C.CFTypeRef]C.CFTypeRef) C.CFDictionaryRef {
	var keys, values []unsafe.Pointer
	for key, value := range m {
		keys = append(keys, unsafe.Pointer(key))
		values = append(values, unsafe.Pointer(value))
	}
	numValues := len(values)
	var keysPointer, valuesPointer *unsafe.Pointer
	if numValues > 0 {
		keysPointer = &keys[0]
		valuesPointer = &values[0]
	}
	return C.CFDictionaryCreate(0, keysPointer, valuesPointer, C.CFIndex(numValues), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

func int64ToCFNumber(i int64) C.CFNumberRef {
	sint := C.SInt64(i)
	return C.CFNumberCreate(0, C.kCFNumberSInt64Type, unsafe.Pointer(&sint))
}

func cfStringRefToString(r C.CFStringRef) string {
	p := C.CFStringGetCStringPtr(r, C.kCFStringEncodingUTF8)
	if p != nil {
		return C.GoString(p)
	}
	return ""
}

func cfErrorRefToError(e C.CFErrorRef) error {
	return fmt.Errorf("CFError %s", cfStringRefToString(C.CFErrorCopyDescription(e)))
}

func bytesToCFDataRef(b []byte) (C.CFDataRef, error) {
	if uint64(len(b)) > math.MaxUint32 {
		return 0, fmt.Errorf("data beyond math.MaxUint32")
	}
	var p *C.UInt8
	if len(b) > 0 {
		p = (*C.UInt8)(&b[0])
	}
	cfData := C.CFDataCreate(0, p, C.CFIndex(len(b)))
	if cfData == 0 {
		return 0, fmt.Errorf("failure in CFDataCreate")
	}
	return cfData, nil
}

func cfDataRefToBytes(r C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(r)), C.int(C.CFDataGetLength(r)))
}

func nilCFErrorRef(r C.CFErrorRef) bool {
	return r == 0
}
