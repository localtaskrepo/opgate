package main

import (
	"fmt"
	"strings"
)

// reasonRules is what a request without a reason prints instead of asking the owner: the guide's request rules.
const reasonRules = `the reason is one concrete sentence the owner reads on the phone: the action and the target, no
  secret, e.g. "Create the DNS record www.example.com -> Cloudflare Pages"
- ask for exactly the fields you need in one call (several references are fine), right before you use them
- on "denied", "expired" or "error": stop and tell the user; don't ask again or try another way to get the secret
- don't guess item names: use the ones the user or the repo's docs give
- never print, log or store the values: use them inside $(...) or through opgate run / op run
More: opgate guide`

// needReason refuses a request without a reason before it reaches the owner; how says where the reason goes.
func needReason(reason, how string) error {
	if strings.TrimSpace(reason) != "" {
		return nil
	}
	return fmt.Errorf("refused, nobody was asked: no reason given (%s). Rules:\n- %s", how, reasonRules)
}

// guide is what `opgate guide` prints: the instructions for agents (any repo, any agent app). guideText fills in the
// build values: {owner} and the vault {vault}.
const guide = `opgate: getting 1Password secrets and ssh keys on this Mac{owner}

Secrets live in the 1Password vault "{vault}". 1Password's own prompts (Touch ID) only work while the owner sits at
the Mac. opgate asks the owner on the phone instead and shows them what you want and why. The owner picks the route
with "opgate mode": auto (Touch ID first, the phone after 30 s; default), phone, or touchid.

Plain "op read", "op run" and "op document get --vault ..." go the same route ("op" is a wrapper around 1Password's
CLI on this Mac); set OPGATE_REASON=... for them. A request without a reason is refused before anyone is asked.
Prefer opgate for several values at once: one approval instead of one per value.

  opgate read --reason "<what you are about to do and why>" "op://{vault}/<item>/<field>" [...]
      prints the values, one per line; use it inside $(...) instead of "op read"
  opgate run --reason "..." --env NAME=op://{vault}/<item>/<field> [--env ...] -- <command> [args]
      runs the command with the values in its environment; use instead of "op run"
  opgate ssh-add --reason "..." [--ttl 1h] "op://{vault}/<key item>/private key"
      loads an ssh key for a while (default 15 min, max 4 h; the owner may change it when approving); then ssh
      with it works. Ask for what the task needs, not the maximum
  opgate read --reason "..." "op://{vault}/<item>?document" > file
      a Document item's file (e.g. an oauth2.txt); write it only to a private temp dir and delete it afterwards
  opgate status      pending requests and loaded keys

Rules:
- The reason is what the owner reads on a small screen: one sentence, concrete (the action and the target), e.g.
  "Create the DNS record www.example.com -> Cloudflare Pages". No secrets in the reason.
- The call waits until the owner decides (up to 10 min). If it fails with "denied", "expired" or "error", tell the
  user and stop; do not ask again in a loop, with other item names, or try another way to get the secret.
- Ask for exactly the fields you need, in one call (several refs are fine), right before you use them. Never print,
  log or store the values (no files, no .env, no exports beyond the one command).
- Not needing opgate: git commits (signed automatically), git push and ssh with the keys the owner
  autoloads work without approval.
- The owner's own 1Password ssh keys are not offered to agents: a host that needs another key (and scripts that
  use it) needs "opgate ssh-add" for that key first. "agent refused operation" or "Permission denied (publickey)"
  from ssh means that key isn't loaded.
- If opgate's service isn't running, it falls back to 1Password (Touch ID) by itself and says so on stderr.
- A locked screen is no reason to wait for the owner or to ask them to unlock the Mac: ask opgate, the owner
  approves on the phone. If opgate says it is waiting for keychain access or can't read the keychain, an opgate
  build waits for a prompt at the Mac: tell the user once, don't restart opgate, and go on with what doesn't need
  it. Don't read secrets from the keychain yourself; if opgate doesn't serve one yet, tell the user.
- Item names: never guess them; ask the user, or check the repo's docs ("opgate creds" lists the known
  credentials); "op item list --vault {vault}" needs Touch ID. A reference to an item that isn't there is refused
  before anyone is asked, with the items whose names look alike. Write names as
  they are, odd characters included ("op://{vault}/Backup bucket (S3)/access key id"): opgate looks up names
  1Password's references can't take (case and punctuation don't matter; an ambiguous name is refused).
- Scripts that need several secrets read them all in one call: "op run --env-file=<file with VAR=op://...>" or
  "opgate read" with several references (one approval; up to 8). "op item get <item> --vault {vault} --fields
  label=<a>,label=<b> --reveal" also goes through opgate; other op commands need Touch ID at the Mac and fail at once
  when nobody is there.
`

func guideText() string {
	owner := ""
	if ownerName != "" {
		owner = " (owner: " + ownerName + ")"
	}
	return strings.NewReplacer("{owner}", owner, "{vault}", vault()).Replace(guide)
}
