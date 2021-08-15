#import <Foundation/Foundation.h>
#import <DeviceCheck/DCAppAttestService.h>

int supported() {
    return DCAppAttestService.sharedService.supported;
}
