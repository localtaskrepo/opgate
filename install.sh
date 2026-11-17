#!/bin/bash
# Build, sign and (re)start opgate (steps and prompts: README.md). This Mac's values come from
# ~/.config/opgate/install.env (README.md, "Configure"); without it, the neutral defaults. Signed with the local
# signing identity (make-signing-cert.sh, once) upgrades keep their permissions; ad-hoc signed (fallback) every build
# is a new app to macOS: allow the keychain item again (at the Mac, or `opgate bootstrap`) and switch Local Network
# off and on for opgate. A build that can't read its keychain store yet isn't installed (handover below).
set -euo pipefail
cd "$(dirname "$0")"
conf=~/.config/opgate/install.env
# defaults the script itself needs (the Go defaults are in config.go; OPGATE_ID matches appID there)
OPGATE_ID=local.opgate
OPGATE_SIGNING_IDENTITY="opgate local signing"
OPGATE_CREDS_REGISTRY=
OPGATE_CREDS_PUSH=
OPGATE_CREDS_LIFECYCLE=
ldflags="-s -w"
if [ -f "$conf" ]; then
  chmod 600 "$conf"
  while IFS= read -r line || [ -n "$line" ]; do
    case $line in '' | '#'*) continue ;; esac
    key=${line%%=*} val=${line#*=}
    case $val in *"'"*) echo "$conf: no ' in values: $line" >&2; exit 1 ;; esac
    case $key in
      OPGATE_ID) ldflags+=" -X 'main.appID=$val'" ;;
      OPGATE_OWNER) ldflags+=" -X 'main.ownerName=$val'" ;;
      OPGATE_PUBLIC_URL) ldflags+=" -X 'main.publicURL=$val'" ;;
      OPGATE_RP_ID) ldflags+=" -X 'main.rpID=$val'" ;;
      OPGATE_ALLOW_FROM) ldflags+=" -X 'main.allowFrom=$val'" ;;
      OPGATE_CONTROL_ITEM) ldflags+=" -X 'main.controlItem=$val'" ;;
      OPGATE_CREDS_REGISTRY) ldflags+=" -X 'main.credsReg=$val'" ;;
      OPGATE_SIGNING_IDENTITY | OPGATE_CREDS_PUSH | OPGATE_CREDS_LIFECYCLE) ;;
      *) echo "$conf: unknown setting: $line" >&2; exit 1 ;;
    esac
    printf -v "$key" %s "$val"
  done < "$conf"
fi
OPGATE_CREDS_LIFECYCLE=${OPGATE_CREDS_LIFECYCLE/#\~/$HOME}
values=${ldflags#-s -w}
echo "build values (~/${conf#"$HOME/"}):${values:- none, the defaults}"
go test -count=1 ./...
mkdir -p ~/.local/bin ~/Library/Logs/opgate ~/.config/opgate
chmod 700 ~/.config/opgate ~/Library/Logs/opgate
touch ~/Library/Logs/opgate/opgate.log && chmod 600 ~/Library/Logs/opgate/*
CGO_ENABLED=1 go build -trimpath -ldflags "$ldflags" -o ~/.local/bin/opgate.new .
# hardened runtime: other processes of this user can't attach to opgate and read its memory.
# With the local signing identity (make-signing-cert.sh) every build is the same app to macOS, so the Local Network
# permission survives upgrades and each build needs one approval for the token: the handover on the phone, or the
# keychain prompt at the Mac ("Always Allow") without one.
SIGN=-
if security find-identity -p codesigning | grep -qF "\"$OPGATE_SIGNING_IDENTITY\""; then SIGN=$OPGATE_SIGNING_IDENTITY; fi
codesign --force --sign "$SIGN" --options runtime --entitlements entitlements.plist --identifier "$OPGATE_ID" ~/.local/bin/opgate.new
codesign -d -r- ~/.local/bin/opgate.new 2>&1 | grep designated
# A new build is a new app to the running build's keychain item: reading it needs a prompt at the Mac, which nobody
# answers while the owner is away and which can't show while the Mac sleeps (-25320). Started without the token,
# opgate would drop the keys the running build holds (no agent could sign), so the running build stays until the new
# one has a keychain item of its own: handed over by the running build after the owner's passkey approval on the phone
# (exit 3: nobody was asked, e.g. no running opgate 0.23.0 or later), else copied after the prompt at the Mac
# (keychain-check). --fresh reads again from a new process without waiting, as the restarted service will.
not_installed() {
  rm -f ~/.local/bin/opgate.new
  echo "not installed: $1; opgate keeps running the old build" >&2
  exit 1
}
rc=0
~/.local/bin/opgate.new handover || rc=$?
if [ "$rc" = 3 ]; then
  ~/.local/bin/opgate.new keychain-check || not_installed "run ./install.sh again at the Mac and answer the keychain prompt for opgate"
elif [ "$rc" != 0 ]; then
  not_installed "the handover wasn't approved; run ./install.sh again and approve it on the phone"
fi
~/.local/bin/opgate.new keychain-check --fresh || not_installed "this build still can't read its own keychain item"
mv ~/.local/bin/opgate.new ~/.local/bin/opgate
install -m 755 ssh-sign ~/.local/bin/opgate-ssh-sign
# the transparent op wrapper: a folder with only `opgate` and `op` (links), first on PATH (README.md)
mkdir -p ~/.local/opgate/bin
ln -sf ~/.local/bin/opgate ~/.local/opgate/bin/opgate
ln -sf ~/.local/bin/opgate ~/.local/opgate/bin/op

# launch agent from a template: label, binary and log path filled in, more ProgramArguments as index=value
# (plutil -replace on an array index inserts, so arguments are removed and inserted)
agent() {
  local template=$1 label=$2 log=$3 plist=~/Library/LaunchAgents/$2.plist arg
  shift 3
  install -m 644 "$template" "$plist"
  plutil -replace Label -string "$label" "$plist"
  plutil -replace StandardOutPath -string "$log" "$plist"
  plutil -replace StandardErrorPath -string "$log" "$plist"
  for arg in "0=$HOME/.local/bin/opgate" "$@"; do
    plutil -remove "ProgramArguments.${arg%%=*}" "$plist"
    plutil -insert "ProgramArguments.${arg%%=*}" -string "${arg#*=}" "$plist"
  done
  launchctl bootout "gui/$(id -u)/$label" 2>/dev/null || true
  # bootout returns before the old instance is gone; bootstrapping too early fails with "5: Input/output error"
  for _ in $(seq 1 20); do launchctl print "gui/$(id -u)/$label" >/dev/null 2>&1 || break; sleep 0.5; done
  launchctl bootstrap "gui/$(id -u)" "$plist"
}
agent opgate.plist "$OPGATE_ID" ~/Library/Logs/opgate/opgate.log
sleep 2
launchctl print "gui/$(id -u)/$OPGATE_ID" | grep -E "state|pid" | head -2
# daily credential check (opgate creds): runs once at load and daily 07:05; only with a registry
if [ -n "$OPGATE_CREDS_REGISTRY" ]; then
  agent opgate-creds.plist "$OPGATE_ID-creds" ~/Library/Logs/opgate/creds.log \
    "4=$OPGATE_CREDS_PUSH" "6=$OPGATE_CREDS_LIFECYCLE"
else
  launchctl bootout "gui/$(id -u)/$OPGATE_ID-creds" 2>/dev/null || true
  rm -f ~/Library/LaunchAgents/"$OPGATE_ID-creds".plist
fi
