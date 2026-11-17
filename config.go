package main

import (
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// This Mac's and its owner's values, set at build time: install.sh reads them from ~/.config/opgate/install.env
// and passes them as -ldflags -X (README.md, "Configure"). They live in the signed binary, not in a file opgate reads
// at run time, so an agent that edits install.env changes nothing until a rebuild, and a rebuild has to be allowed
// at the Mac before it can read the token. The defaults work on the Mac alone (approval page on localhost).
var (
	appID       = "local.opgate"          // launch agent label, keychain service and code signing identifier
	ownerName   = ""                      // named in `opgate guide`
	publicURL   = "http://localhost:8742" // the approval page as the phone opens it
	rpID        = "localhost"             // WebAuthn relying party ID: the page's host name
	allowFrom   = ""                      // comma-separated addresses besides localhost that may reach the page (the reverse proxy)
	controlItem = "op://Agents/opgate"    // 1Password item with the approving passkeys and the autoload keys
	credsReg    = ""                      // opgate creds: the credential registry (~/ allowed; none: opgate creds is off)
)

// Config holds opgate's non-secret settings (~/.config/opgate/config.json; every field has a default).
// What may be released without an approval and which passkeys may approve is NOT configured here (a file agents
// can edit) but in the 1Password item ControlItem, which only the owner can change.
type Config struct {
	Socket        string   `json:"socket"`         // request API (unix socket, 0600)
	AgentSocket   string   `json:"agent_socket"`   // ssh agent (opgate's keys + the 1Password agent behind them)
	UpstreamAgent string   `json:"upstream_agent"` // the 1Password ssh agent
	Listen        string   `json:"listen"`         // approval page (HTTP; TLS is the reverse proxy's)
	AllowFrom     []string `json:"allow_from"`     // remote addresses allowed to reach the page (the reverse proxy, localhost)
	PublicURL     string   `json:"public_url"`     // the approval page as the phone opens it
	RPID          string   `json:"rp_id"`          // WebAuthn relying party ID
	ControlItem   string   `json:"control_item"`
	AuditLog      string   `json:"audit_log"`
	PendingTTL    Duration `json:"pending_ttl"` // how long a request waits for a decision
	MaxSSHTTL     Duration `json:"max_ssh_ttl"`
	MaxPerHour    int      `json:"max_per_hour"`
	RealOp        string   `json:"real_op"`    // the 1Password CLI (Homebrew cask 1password-cli), never the wrapper
	OpTimeout     Duration `json:"op_timeout"` // mode auto: how long 1Password gets before the phone is asked
	AwayIdle      Duration `json:"away_idle"`  // mode auto: no input for this long (or a locked screen) = away
}

// Duration is a time.Duration that reads "10m" from JSON.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func home(p string) string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, p)
}

// listenAddr: without a reverse proxy only localhost may reach the page, so opgate listens on localhost alone.
func listenAddr(allowFrom string) string {
	if strings.TrimSpace(allowFrom) == "" {
		return "127.0.0.1:8742"
	}
	return ":8742"
}

func defaultConfig() Config {
	return Config{
		Socket:        home(".config/opgate/opgate.sock"),
		AgentSocket:   home(".ssh/opgate-agent.sock"),
		UpstreamAgent: home("Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock"),
		Listen:        listenAddr(allowFrom),
		AllowFrom:     append(strings.FieldsFunc(allowFrom, func(r rune) bool { return r == ',' || r == ' ' }), "127.0.0.1", "::1"),
		PublicURL:     publicURL,
		RPID:          rpID,
		ControlItem:   controlItem,
		AuditLog:      home("Library/Logs/opgate/audit.jsonl"),
		PendingTTL:    Duration{10 * time.Minute},
		MaxSSHTTL:     Duration{4 * time.Hour},
		MaxPerHour:    30,
		RealOp:        "/opt/homebrew/bin/op",
		OpTimeout:     Duration{30 * time.Second},
		AwayIdle:      Duration{2 * time.Minute},
	}
}

func loadConfig() (Config, error) {
	// The file can only tune timing: everything that decides who may approve, which op runs or
	// how long keys live is compiled in (agents can write this file; the build values above: install.env).
	c := defaultConfig()
	b, err := os.ReadFile(home(".config/opgate/config.json"))
	if err == nil {
		var f struct {
			OpTimeout *Duration `json:"op_timeout"`
			AwayIdle  *Duration `json:"away_idle"`
		}
		if err = json.Unmarshal(b, &f); err != nil {
			log.Printf("~/.config/opgate/config.json ignored: %v", err) // a typo must not take opgate down
			err = nil
		} else {
			if f.OpTimeout != nil && f.OpTimeout.Duration >= 5*time.Second && f.OpTimeout.Duration <= 5*time.Minute {
				c.OpTimeout = *f.OpTimeout
			}
			if f.AwayIdle != nil && f.AwayIdle.Duration >= 30*time.Second && f.AwayIdle.Duration <= time.Hour {
				c.AwayIdle = *f.AwayIdle
			}
		}
	} else if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	if s := os.Getenv("OPGATE_SOCKET"); s != "" { // tests
		c.Socket = s
	}
	return c, err
}

// vault is the 1Password vault of the control item, the one agents read from.
func vault() string {
	v, _, _ := strings.Cut(strings.TrimPrefix(controlItem, "op://"), "/")
	return v
}
