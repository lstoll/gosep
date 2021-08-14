# gosep

Go library for various [Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web) / other macOS hardware security items

### SEP

Library for managing and using secure-enclave (i.e hardware-backed) keys

## Codesigning

Binaries need to be signed (and have entitlements?) to use these functionalities.

To get a cert:
* Go to https://developer.apple.com/account/resources/certificates/add
* Select "Developer ID Application"
* Create a CSR as described https://help.apple.com/developer-account/#/devbfa00fef7
* Download result, and open it

List available signing identites:
```
security find-identity -v -p codesigning
```

Entitlements for SEP (Team ID is after name in identity list) e.g:

```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>com.apple.application-identifier</key>
        <string>TEAMID.com.domain.app</string>
        <key>com.apple.developer.team-identifier</key>
        <string>TEAMID</string>
        <key>keychain-access-groups</key>
        <array>
                <string>TEAMID.com.domain.app</string>
        </array>
</dict>
</plist>
```

A provisioning profile is also required, as restricted entitlements are needed:
* Go to https://developer.apple.com/account/resources/identifiers/add/bundleId
* Add an identifier for this app.
* For apps using attest, that capability will need to be added explicitly.
* Go to https://developer.apple.com/account/resources/profiles/add
* Create a new provisioning profile of type Developer ID Application
* Bind to the cert from above
* Copy in to the bundle, at path `Contents/embedded.provisionprofile`

Sign with identity
```
codesign --force --identifier com.domain.app --deep --entitlements entitlements.plist --sign <id> <bundle root folder>
```
