# Security

## What opgate protects against

opgate stands between agents and a 1Password vault: an agent gets a secret or an ssh key only after the owner has
seen what it wants, why and who asks, and approved with a passkey. It guards against agents' **mistakes and
overreach**: reading secrets they weren't given, using a key for longer or for something else than approved, or
asking without saying why.

It does **not** guard against a hostile process running as the same macOS user. Such a process could re-sign the real
binary with the local signing key (codesign uses it without asking) and wait for the owner to approve its handover,
or simply wait for a secret it was given. Run agents as the owner only as far as you trust them
with that.

## Trust anchors

Agents run as the same user and can edit any file opgate reads, so what decides access lives where they can't write:

- **The control item** in 1Password (`OPGATE_CONTROL_ITEM`), editable only by the owner: `passkeys` (which passkeys
  may approve) and `autoload` (which ssh keys load without approval). The service account only reads.
- **The service account token** in a login keychain item of each build's own (account `store-<build>`), which only
  the build that created it reads without a prompt; any other build or program gets a dialog at the Mac. How signing
  keeps the access list stable and why it uses a local identity, not a Developer ID: README, "Why it is signed this
  way".
- **A new build gets the token only through a handover** (`opgate handover`, run by `install.sh`): the running
  opgate asks the owner with a push "New opgate build", and hands its store over only after a passkey approval of
  that request, and only to a running process signed like itself whose executable is the build named in the request.
  The approval page shows the process chain, so a rebuild nobody started is a request to deny. Without a running
  opgate that can hand over (the first install), the new build reads the old item through the dialog at the Mac.
- **Build values** (public URL, passkey RP ID, allowed proxy addresses, control item) are compiled into the signed
  binary. Changing them is a rebuild, and a rebuild needs that approval.
- **Notification settings and the Web Push key** are in the same keychain item, so agents can't read or silence
  notices.

## How an approval is authenticated

- Approve is a WebAuthn assertion with **user verification required**, checked against the passkeys in the control
  item for the RP ID compiled in, and bound to that one request. A wrong request, an unknown passkey or missing user
  verification fails (`go test` covers each).
- **Enrolling** a passkey needs the key in the link `opgate enroll` prints; a process that sees the enrollment ID
  can't register its own passkey. The new passkey only counts once the owner adds it to the control item.
- **Pushes carry only links** (end-to-end encrypted Web Push, RFC 8291). Anyone who could send one still can't
  approve. On a desktop, the passkey prompt starts by itself only with the one-time token from opgate's own push.
- **The page** answers only its own host name and localhost, from localhost or the configured proxy addresses,
  refuses POSTs from any origin but its own pages and sends a strict Content-Security-Policy.
- **Unlocking** the overview's details and changing notification settings use the same passkeys (10 minutes, an
  HttpOnly, Secure, SameSite=Strict cookie held in memory) and are audited.
- **Deny and Revoke need no passkey**: they only take access away.

## What needs no approval

- **Autoloaded ssh keys** (the control item's `autoload`) sign for any process of the user, agents included, without
  asking. Every use is in the audit log and in a daily notice. List only keys whose use you accept unattended (for
  example git signing).
- **"Same again"** grants, for the time the owner picked, cover the same references from the same script (path and
  content hash) and subcommand, or the same full command, in the same folder and agent session. Each reuse updates a
  notice.
- **Touch ID** (modes `auto` and `touchid`) leaves the decision to 1Password's own prompt at the Mac.

## Known limits

- A secret, once delivered, is the agent's: opgate can revoke a grant or unload a key, not take a value back.
- Who asked comes from the kernel (executable paths, start times, working folders); command lines are shown but
  can be faked.
- The audit log and history are informational: any process of the user can write to them.
- The credential registry (`opgate creds`) is a report only; it never feeds approvals.
- **The approval page has no login for reading.** Anyone who reaches it sees pending requests (reasons, command
  lines, folders, item names) and the history, and can deny requests and revoke grants and keys; only approving and
  the unlocked details need a passkey. Behind a reverse proxy every visitor has the proxy's address. Keep the page
  on localhost, the home network or a VPN, or put authentication in the proxy.
- **Agents are recognised by name** from the process chain: Claude Code, Codex and Kilo (`identity.go`). Any
  other agent counts as the owner's own session and is offered the 1Password agent's ssh keys (1Password's own
  prompt still applies). Its requests through `opgate read`/`run` and the `op` wrapper are gated as for any caller.
- The approval duration the owner picks on the page isn't part of the signed passkey assertion; a proxy on the path
  could lengthen it, up to the caps (1 h for secrets, 4 h for ssh keys).

## Reporting a vulnerability

Please don't open a public issue. Report it privately through a GitHub security advisory on this repository, with
what you found, how to reproduce it and the impact you expect. Responses are best-effort.
