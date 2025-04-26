#!/bin/bash
set -e

# Configuration (modify these values)
APP_NAME="gensepidentity"
BUNDLE_ID="com.github.lstoll.gosep.gensepidentity" # Change to your domain
IDENTITY_HASH=B14D2954A971921795273A7A18941387F8539657 # security find-identity -v -p codesigning
TEAM_ID=MZXW569JYG

echo "Using Team ID: $TEAM_ID"

# Create bundle structure
echo "Creating application bundle..."
mkdir -p "$APP_NAME.app/Contents/MacOS"
mkdir -p "$APP_NAME.app/Contents/Resources"

# Build the Go application
echo "Building Go application..."
go build -o "$APP_NAME.app/Contents/MacOS/$APP_NAME" ./cmd/gensepidentity

# Create Info.plist
cat > "$APP_NAME.app/Contents/Info.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>$APP_NAME</string>
    <key>CFBundleIdentifier</key>
    <string>$TEAM_ID.$BUNDLE_ID</string>
    <key>CFBundleName</key>
    <string>$APP_NAME</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
</dict>
</plist>
EOF

# Create entitlements file
cat > "entitlements.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.application-identifier</key>
    <string>$TEAM_ID.$BUNDLE_ID</string>
    <key>com.apple.developer.team-identifier</key>
    <string>$TEAM_ID</string>
    <key>keychain-access-groups</key>
    <array>
        <string>$TEAM_ID.$BUNDLE_ID</string>
    </array>
</dict>
</plist>
EOF

# Check if the user has a provisioning profile
if [ ! -f "$APP_NAME.app/Contents/embedded.provisionprofile" ]; then
  echo "IMPORTANT: You need to create a provisioning profile from Apple Developer Portal"
  echo "For SEP functionality, visit https://developer.apple.com/account/resources/profiles/add"
  echo "and create a Developer ID Application profile, then add it to:"
  echo "$APP_NAME.app/Contents/embedded.provisionprofile"
fi

# Sign the application
echo "Signing application bundle..."
codesign --force --identifier "$TEAM_ID.$BUNDLE_ID" --deep --entitlements entitlements.plist --sign "$IDENTITY_HASH" "$APP_NAME.app"

# Verify signature
echo "Verifying signature..."
codesign --verify --deep --strict "$APP_NAME.app"
if [ $? -eq 0 ]; then
  echo "✓ Application bundle successfully signed!"
  echo "Bundle location: $(pwd)/$APP_NAME.app"
else
  echo "✗ Signature verification failed."
fi
