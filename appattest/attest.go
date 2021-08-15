package appattest

/*
#cgo CFLAGS: -x objective-c -mmacosx-version-min=11.0 -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework DeviceCheck
#import <Foundation/Foundation.h>
#import <DeviceCheck/DCAppAttestService.h>
#import <stdlib.h>

#import "appattest.h"
*/
import "C"

func Supported() bool {
	return C.supported() != 0
}
