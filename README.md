# opgate

opgate gives agents on a Mac (it recognises Claude Code, Codex and Kilo) access to a 1Password vault and to ssh
keys, but only after the owner approves each request on the phone with a passkey. It runs as a launch agent, holds a
read-only 1Password service account token in the login keychain, and wraps `op` so ordinary commands keep working.
What it protects and how approval is authenticated: [SECURITY.md](SECURITY.md).

## How it works

- **Asking.** An agent runs `opgate read --reason "…" op://<vault>/<item>/<field>` (values on stdout),
  `opgate run --reason "…" --env VAR=op://… -- cmd args` (values in cmd's environment) or
  `opgate ssh-add --reason "…" [--ttl 1h] op://…/private key` (the key in opgate's ssh agent for 1 min to 4 h,
  default 15 min). A request without a reason (`--reason` or `$OPGATE_REASON`), or for a vault or item that doesn't exist, is refused
  before anyone is asked. The call blocks until the owner decides, at most 10 minutes. `opgate guide` prints the
  instructions for agents.
- **Approving.** The owner gets a push with what, why and who asked (the asking process chain, read from the
  kernel), opens the approval page and approves with a passkey, once or as "same again" for 15 minutes to an hour
  (the same references from the same script or command, folder and agent session). Deny needs no passkey.
- **The `op` wrapper.** `~/.local/opgate/bin/op` routes `op read`, `op run`, `op document get` and
  `op item get … --fields … --reveal` through opgate and passes every other command unchanged to
  `/opt/homebrew/bin/op`.
- **Modes** (`opgate mode`): `auto` (default) tries 1Password's own Touch ID prompt when someone is at the Mac (the phone
  if it isn't answered in `op_timeout`) and the phone straight away when nobody is; `phone`; `touchid` (1Password only).
- **ssh agent** at `~/.ssh/opgate-agent.sock`: opgate's keys first, then the 1Password agent's keys for the
  owner's own sessions; recognised agents only get opgate's keys (an agent opgate doesn't recognise counts as the
  owner's session, see [SECURITY.md](SECURITY.md)). Keys listed in the control item's `autoload` field load at
  start without approval (for example a key for git signing, `ssh-sign` is the `gpg.ssh.program` for it).
- **Activity and revoking.** Every use of a grant or key updates one notice. Revoke on the notice or page ends a
  grant or unloads a key; the overview page lists open requests, live grants and loaded keys, and the history.
- **Credential map** (optional, `opgate creds`): checks a registry of credentials (where stored, who uses them,
  expiry, last use; no values) and shows it on the overview (below).
- **Project names** on the page and in notices: the repository's lotar `ui.name` and icon (`.tasks/config.yml`)
  when it has one, else the folder below `~/Development`, else the folder name.

## Requirements

- macOS on Apple silicon, Xcode Command Line Tools (`codesign`, cgo), Go (version in `go.mod`), Homebrew's
  `1password-cli` at `/opt/homebrew/bin/op` (the path is fixed), and the 1Password desktop app with
  Settings > Developer > **Integrate with 1Password CLI** on (`opgate bootstrap` reads the token through it, with
  Touch ID).
- In 1Password:
  - A vault for the agents' secrets (the default is called `Agents`; any name works with `OPGATE_CONTROL_ITEM`).
  - A [service account](https://developer.1password.com/docs/service-accounts/) with **read-only** access to that
    vault. Save its token (`ops_…`) in an item of a vault the service account can't read, for example a field
    `credential` in your private vault.
  - The control item in the agents' vault (default `op://Agents/opgate`), with two text fields. Only the owner can
    edit it: it decides which passkeys may approve and which ssh keys load without approval.
    - `passkeys`: a JSON list, one element per `opgate enroll` (install step 6). Start with `[]`.
    - `autoload`: one `op://` reference to an ssh key per line, `#` comments; may be empty. For example
      `op://Agents/git signing key/private key`.
- For approvals away from the Mac: an HTTPS name for the approval page and a reverse proxy for it (below). Without
  one, the page is only on `http://localhost:8742`.

## Configure

This Mac's and its owner's values go in `~/.config/opgate/install.env` (mode 600, outside the repo; one
`KEY=value` per line, no quotes, `#` comments). `install.sh` compiles them into the binary (`-ldflags -X`) and prints
them before it builds. A missing key keeps its default; an unknown key stops the install.

| Key | Default | What |
|---|---|---|
| `OPGATE_ID` | `local.opgate` | launch agent label (the credential check: `<id>-creds`), keychain service and signing identifier. Changing it is a new app to macOS: new keychain item (`opgate bootstrap` again), Local Network again |
| `OPGATE_OWNER` | none | the owner's name in `opgate guide` |
| `OPGATE_PUBLIC_URL` | `http://localhost:8742` | the approval page as the phone opens it (links in notifications, passkey origin) |
| `OPGATE_RP_ID` | `localhost` | passkey relying party ID: the page's host name. Enrolled passkeys only work for the ID they were made for |
| `OPGATE_ALLOW_FROM` | none | addresses besides localhost that may reach the page (the reverse proxy), comma-separated |
| `OPGATE_CONTROL_ITEM` | `op://Agents/opgate` | the control item; its vault is the one agents are told to use |
| `OPGATE_SIGNING_IDENTITY` | `opgate local signing` | the code-signing identity (`make-signing-cert.sh` reads it too) |
| `OPGATE_CREDS_REGISTRY` | none | the credential registry `opgate creds` checks (`~/` allowed). None: `opgate creds` is off (or `--file REGISTRY`) and no daily check is installed |
| `OPGATE_CREDS_PUSH` | none | `opgate creds --push` target of the daily credential check (none: no push) |
| `OPGATE_CREDS_LIFECYCLE` | none | `opgate creds --lifecycle` file of the daily check (`~/` allowed; none: no comparison) |

Why compiled in and not read at run time: agents run as the same user and can edit any file opgate reads. Values in
the signed binary change only with a rebuild, and a rebuild is a new app to the keychain, so it gets the token only
after the owner approves its handover on the phone or allows it at the Mac. `~/.config/opgate/config.json` (read at
run time) only tunes timing: `op_timeout` (mode auto: how long 1Password's prompt gets before the phone is asked, 5 s
to 5 min) and `away_idle` (no input for this long counts as away, 30 s to 1 h), as Go durations (`"30s"`).

## Approval page behind HTTPS

Passkeys need HTTPS (or localhost), so a phone reaches the page through a TLS reverse proxy you run (Caddy, nginx)
on a name like `opgate.example.net`, reachable from the phone at home or over a VPN.

**Never make the page reachable from the internet** (no public tunnel or port forward) unless the proxy itself
authenticates visitors. Approving needs a passkey, but reading does not: anyone who reaches the page sees pending
requests with their reasons, command lines, folders and item names, and the history, and can deny requests and
revoke grants and keys. All of that arrives from the proxy's address, so opgate can't tell visitors apart.


- The proxy forwards to port 8742 on the Mac and keeps the `Host` header: opgate answers only its own host name and
  localhost (no DNS rebinding) and refuses POSTs from other origins.
- Set `OPGATE_PUBLIC_URL=https://opgate.example.net`, `OPGATE_RP_ID=opgate.example.net` and
  `OPGATE_ALLOW_FROM=<the proxy's address>`: opgate then listens on all interfaces but answers only localhost and
  these addresses. Without `OPGATE_ALLOW_FROM` it listens on `127.0.0.1` only.
- The proxy passes `text/event-stream` through unbuffered (the page's live updates).
- Enroll passkeys after the RP ID is set: a passkey only works for the ID it was made for.

## Install

At the Mac, signed in as the user opgate runs for:

1. **Configure:** write `~/.config/opgate/install.env` (above), or skip it to try opgate on the Mac alone.
2. **Create the signing identity, once:** `./make-signing-cert.sh`. It creates the self-signed code-signing
   certificate "opgate local signing" (or `OPGATE_SIGNING_IDENTITY`) in the login keychain. macOS asks for your login
   password to trust it for code signing: enter it. If the identity already exists, the script says so and stops.
3. **Build and install:** `./install.sh`. It runs the tests, builds `~/.local/bin/opgate` with the values from
   `install.env`, signs it with that identity, installs the `op` wrapper (`~/.local/opgate/bin`, put it first on
   `PATH`) and the launch agents `<OPGATE_ID>` and, with a registry, `<OPGATE_ID>-creds` (from the templates `opgate.plist` and
   `opgate-creds.plist`), and starts opgate. Run it again for every upgrade. Before installing, the new build gets
   a keychain item of its own: `opgate handover` asks the running opgate for its keychain store, the
   owner approves that with the passkey on the phone, and the new build writes it into its own item, which it
   reads without a prompt. With no running opgate that can hand over, it reads the running build's item instead
   (`opgate keychain-check`, prompt below) and keeps a copy. Either way it then reads its own item from a new
   process without a prompt (`keychain-check --fresh`). If any of that fails (handover denied or expired, prompt
   unanswered, the Mac asleep: -25320), the install stops and the running opgate keeps its keys: restarting would
   leave opgate without its token and no agent could sign.
4. **Answer the prompts:**
   - codesign asks to sign with the key "opgate local signing" (first signing only): enter your login password and
     click **Always Allow**. That lets codesign, and only codesign, use the key without asking from then on.
   - The handover (every new build, during `install.sh`): a push "New opgate build" on the phone; approve it with the
     passkey. It expires like any request; then the build isn't installed.
   - opgate asks to use the confidential information in its keychain item `<OPGATE_ID>` (only without a handover:
     the first install): enter your login password and click **Allow** or **Always Allow**. Without an answer within 2 minutes the build isn't installed.
   - With `OPGATE_ALLOW_FROM` set, the macOS firewall asks whether opgate may accept incoming network connections
     (first start): **Allow**.
   - Only if the credential check probes services on your LAN: System Settings > Privacy & Security >
     **Local Network**, switch opgate on. This stays on across upgrades.
5. **Store the token, once:** `opgate bootstrap "op://<vault>/<token item>/credential"`. opgate checks the
   signature of `/opt/homebrew/bin/op`, reads the token through it (1Password asks for Touch ID) and stores it in
   its keychain item.
6. **Enroll the phone, once:** `opgate enroll --name <phone>`, open the printed link on the phone, create the
   passkey, and add the printed JSON object as an element of the control item's `passkeys` list
   (`[{…}]`, or `[{…}, {…}]` for a second device).
7. **Turn on notifications:** on the phone open the approval page and install it as an app (Android, Chrome:
   ⋮ > Install app; opgate is tested with Chrome. On an iPhone, web push needs the page added from Safari with
   Share > Add to Home Screen, iOS 16.4 or later). Open Notifications, unlock with the passkey and turn
   notifications on (a test push follows). The same in a
   desktop browser for notices on the Mac. Without a device nobody is notified and asking agents get a warning.
8. **Point ssh and git at opgate (optional):** `IdentityAgent ~/.ssh/opgate-agent.sock` in the ssh config; for
   commit signing with an autoloaded key, `git config --global gpg.ssh.program ~/.local/bin/opgate-ssh-sign`.
   For the `op` wrapper, put `~/.local/opgate/bin` ahead of Homebrew on `PATH`, in zsh:
   `echo 'export PATH="$HOME/.local/opgate/bin:$PATH"' >> ~/.zshrc`.
9. **Check:** `opgate status` shows the service, the keychain state and the loaded keys.

Without the signing identity, `install.sh` signs ad hoc. Then every build is a new app to macOS: you answer the
keychain prompt again (or run `opgate bootstrap` again) and switch Local Network off and on for opgate.

## Why it is signed this way

opgate's secret is the 1Password token in the login keychain. macOS gives a keychain item only to the apps on the
item's access list, and with no Apple team ID it lists each build by its code hash. The signing decides what
"the same app" means to macOS.

- **A local, self-signed identity, not an Apple Developer ID.** A Developer ID carries a team ID, and the keychain
  then trusts *any* binary signed by that team, so anything signed with that certificate could pass as opgate and
  read the token. That certificate also signs other software and sits in a CI system's secrets. The local
  identity signs opgate only. If agents sign other local builds with your Developer ID, the keychain would trust
  those as opgate too. The cost of the local identity is one approval per build (the handover on the phone, or
  the keychain prompt at the Mac without one); the other grants survive new builds.
- **Its key never leaves the Mac.** `make-signing-cert.sh` creates it in the login keychain and deletes the
  temporary files. The private key trusts `/usr/bin/codesign` only: codesign signs without asking, while
  `security export` and every other use ask for the login password, so nothing can copy the key off the Mac
  silently. (`security import` without `-T` would trust `security` itself and allow a silent export.)
- **The fixed identifier keeps the grants.** Every build is signed as `<OPGATE_ID>` with the same
  certificate, so it has the same designated requirement. The Local Network permission and opgate's place on its
  keychain item's access list survive upgrades.
- **The per-build approval is the guard.** Since codesign signs without asking, any process of the user could
  sign a modified opgate with this key. Such a build still has a new code hash, so it gets the token only through a
  handover the owner approves with the passkey on the phone, or the prompt at the Mac. A rebuild you didn't start
  is a request you deny. The running opgate hands over only to a running process signed like itself whose
  executable is the build named in the request (`handover.go`); the approval page shows the process chain.
- **One keychain item per build.** An item a build created itself it reads without a prompt, so each build keeps
  its store in its own item, account `store-<build>` (the first 24 hex digits of the executable's SHA-256). The
  serving build deletes the items of older builds (`security delete-generic-password`: the keychain API refuses even
  the creator).
- **Hardened runtime.** Other processes of the user can't attach to opgate or inject code into it. The
  entitlements (`entitlements.plist`) only allow the executable memory the 1Password SDK's WebAssembly runtime
  needs.

opgate guards against agents' mistakes and overreach, not against a hostile process running as the owner
([SECURITY.md](SECURITY.md)).

To check the key's access list: `security dump-keychain -a ~/Library/Keychains/login.keychain-db`, the class
0x00000010 entry for "opgate local signing": the entry with `sign export_clear` lists `applications (1):
/usr/bin/codesign`. `TestSigningKeyImportTrustsOnlyCodesign` (`go test`) runs the script's import against a throwaway
keychain and checks the same list.

## Files

- `~/Library/Logs/opgate/opgate.log`: the service log; `audit.jsonl` next to it: every request, decision and key use
  (no values).
- `~/.config/opgate/`: `install.env` (build values), `config.json` (timing), `mode`, `creds-latest.json` (the last
  credential check).
- Uninstall: point `IdentityAgent` and `gpg.ssh.program` back to what they were and take `~/.local/opgate/bin` off
  `PATH`, then:

  ```sh
  launchctl bootout gui/$(id -u)/<OPGATE_ID>; launchctl bootout gui/$(id -u)/<OPGATE_ID>-creds
  rm ~/Library/LaunchAgents/<OPGATE_ID>.plist ~/Library/LaunchAgents/<OPGATE_ID>-creds.plist
  rm -r ~/.local/opgate ~/.local/bin/opgate ~/.local/bin/opgate-ssh-sign
  ```

  The keychain items (Keychain Access, service `<OPGATE_ID>`), the signing identity ("opgate local signing") and
  `~/.config/opgate` and `~/Library/Logs/opgate` stay until you delete them.

## Credential check (optional)

`opgate creds` checks a registry of credentials, a JSON file (`OPGATE_CREDS_REGISTRY`) that holds no secret values:

```json
{"credentials": [
  {"id": "dns-token", "title": "DNS API token", "tier": "A", "store": "op://Agents/DNS token/credential",
   "used_by": ["dns script"], "expires": "2027-06-01"},
  {"id": "site-cert", "title": "Site certificate", "tier": "B", "store": "~/.config/site", "used_by": ["web"],
   "probe": {"type": "tls", "address": "example.net:443", "server_name": "example.net"}}
]}
```

Tier A is a credential in 1Password (read only through opgate, never by a probe), tier B a narrowly scoped token in
a file. Probe types: `http`, `tls`, `rdap`, `grafana_sa`, `metric` (a Prometheus-style query against its
`url`) and `command`; their fields are in `creds.go` (`Probe`). `opgate creds --help` lists the flags.
With a registry, `install.sh` installs a daily check (`<OPGATE_ID>-creds`); the overview shows its last result.
The registry is a report only and never feeds approvals.

## Develop

- Tests: `go test ./...` (macOS; a software passkey checks that a wrong request, an unknown passkey and missing user
  verification all fail).
- Lint: `golangci-lint run ./...` (config `.golangci.yml`); `golangci-lint fmt` fixes formatting.
- CI: `.github/workflows/ci.yml` builds, tests and lints on a macOS runner.
- Sample pages to look at: `OPGATE_DUMP=<path prefix> go test -run TestDump .` writes the approval, overview and
  settings pages as `<path prefix>-<name>.html`.

## License

MIT ([LICENSE](LICENSE)).
