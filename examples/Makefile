.PHONY: all
all: bundled/sepkey.app bundled/attested-app.app

.PHONY: bundled/sepkey.app
bundled/sepkey.app: sepkey
	mkdir -p $@/Contents/MacOS
	CGO_ENABLED=1 GOARCH=amd64 go build -o $@/Contents/MacOS/amd64 ./$<
	CGO_ENABLED=1 GOARCH=arm64 go build -o $@/Contents/MacOS/arm64 ./$<
	lipo -create -output $@/Contents/MacOS/$< $@/Contents/MacOS/amd64 $@/Contents/MacOS/arm64
	rm $@/Contents/MacOS/amd64 $@/Contents/MacOS/arm64
	codesign --force --identifier li.lds.gosep.sepkey --deep --entitlements $</entitlements.plist --sign ${CODESIGN_ID} $@

.PHONY: bundled/attested-app.app
bundled/attested-app.app: attested-app
	mkdir -p $@/Contents/MacOS
	CGO_ENABLED=1 GOARCH=amd64 go build -o $@/Contents/MacOS/amd64 ./$<
	CGO_ENABLED=1 GOARCH=arm64 go build -o $@/Contents/MacOS/arm64 ./$<
	lipo -create -output $@/Contents/MacOS/$< $@/Contents/MacOS/amd64 $@/Contents/MacOS/arm64
	rm $@/Contents/MacOS/amd64 $@/Contents/MacOS/arm64
	codesign --force --identifier li.lds.gosep.attested-app --deep --entitlements $</entitlements.plist --sign ${CODESIGN_ID} $@
