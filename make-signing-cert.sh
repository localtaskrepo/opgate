#!/bin/bash
# Owner, once: creates the self-signed code-signing identity in the login keychain: "opgate local signing", or
# OPGATE_SIGNING_IDENTITY from ~/.config/opgate/install.env (README.md, "Configure").
# Signed with it, every opgate build has the same designated requirement, so macOS keeps the keychain item access
# and the Local Network permission across upgrades. The private key trusts only codesign:
# it signs without asking, every other use (`security export` too) asks for the login password. Without -T,
# `security import` would trust itself and export the key silently. Background: README.md.
set -euo pipefail
NAME=
if [ -f ~/.config/opgate/install.env ]; then
  NAME=$(sed -n 's/^OPGATE_SIGNING_IDENTITY=//p' ~/.config/opgate/install.env | tail -1)
fi
NAME=${NAME:-opgate local signing}
KC="$HOME/Library/Keychains/login.keychain-db"
if security find-certificate -c "$NAME" "$KC" >/dev/null 2>&1; then
  echo "\"$NAME\" already exists"; exit 0
fi
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/cfg" <<CFG
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no
[dn]
CN = $NAME
[ext]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
CFG
/usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -keyout "$tmp/key.pem" -out "$tmp/cert.pem" -config "$tmp/cfg" 2>/dev/null
pass=$(/usr/bin/openssl rand -hex 16)
/usr/bin/openssl pkcs12 -export -inkey "$tmp/key.pem" -in "$tmp/cert.pem" -out "$tmp/id.p12" -passout "pass:$pass"
security import "$tmp/id.p12" -k "$KC" -P "$pass" -f pkcs12 -T /usr/bin/codesign >/dev/null
# trust it for code signing (user domain; macOS asks for the password)
security add-trusted-cert -p codeSign -k "$KC" "$tmp/cert.pem"
security find-identity -p codesigning | grep "$NAME"
