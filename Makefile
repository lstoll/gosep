.PHONY: packaged/keychain-basic.app
packaged/keychain-basic.app:
	mkdir -p packaged/keychain-basic.app/Contents/MacOS
	CGO_ENABLED=1 GOARCH=amd64 go build -o packaged/keychain-basic.app/Contents/MacOS/amd64 ./examples/keychain-basic
	CGO_ENABLED=1 GOARCH=arm64 go build -o packaged/keychain-basic.app/Contents/MacOS/arm64 ./examples/keychain-basic
	lipo -create -output packaged/keychain-basic.app/Contents/MacOS/keychain-basic packaged/keychain-basic.app/Contents/MacOS/amd64 packaged/keychain-basic.app/Contents/MacOS/arm64
	rm packaged/keychain-basic.app/Contents/MacOS/amd64 packaged/keychain-basic.app/Contents/MacOS/arm64
	codesign --force --identifier li.lds.keychain-basic --deep --entitlements entitlements.plist --sign ${CODESIGN_ID} packaged/keychain-basic.app
