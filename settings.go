package main

// The notifications page (/settings): which devices get opgate's pushes and which kinds of notice each one gets.
// Anyone who can reach the page can look; every change (a new
// device, levels, rename, remove, test) needs the passkey unlock of the overview page (10 minutes).

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

type segOpt struct {
	Value, Label string
	Checked      bool
}

type catRow struct {
	Key, Name, Help string
	Opts            []segOpt
}

type devView struct {
	ID, Name, Kind, Added, Hash string
	Gone                        bool
	Status, StatusLevel         string // ok, warn, bad, "" (nothing sent yet)
	Rows                        []catRow
}

type settingsData struct {
	Version               string
	Unlocked              bool
	UnlockedUntil         string
	Key, KeyErr, PrefsErr string
	Devices               []devView
}

func endpointHash(endpoint string) string {
	h := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(h[:8])
}

func segOpts(values []string, labels map[string]string, cur string) []segOpt {
	var out []segOpt
	for _, v := range values {
		out = append(out, segOpt{Value: v, Label: labels[v], Checked: v == cur})
	}
	return out
}

func (b *Broker) settingsPage(req *http.Request) settingsData {
	now := b.now()
	d := settingsData{Version: version}
	if until := b.unlockedUntil(req); !until.IsZero() {
		d.Unlocked, d.UnlockedUntil = true, until.Local().Format("15:04")
	}
	n := b.push
	key, err := n.push.PublicKey()
	if err != nil {
		d.KeyErr = err.Error()
	}
	d.Key = key
	s, err := n.prefs.get()
	if err != nil {
		d.PrefsErr = err.Error()
	}
	for _, dev := range s.Devices {
		v := devView{ID: dev.ID, Name: dev.Name, Kind: "Desktop", Added: dev.Added.Local().Format("Jan 2"), Hash: endpointHash(dev.Endpoint),
			Gone: !dev.Gone.IsZero()}
		if dev.Mobile {
			v.Kind = "Phone"
		}
		st := n.prefs.statusOf(dev.ID)
		switch {
		case v.Gone:
			v.Status, v.StatusLevel = "Stopped "+ago(now, dev.Gone)+": the browser ended the subscription. Turn notifications on again on that device.", "bad"
		case st.Fails > 0:
			v.Status, v.StatusLevel = fmt.Sprintf("Failing (%d× in a row, last %s): %s", st.Fails, clock(now, st.LastFail), short(st.Err, 200)), "warn"
		case !st.LastOK.IsZero():
			v.Status, v.StatusLevel = "Last delivered "+clock(now, st.LastOK), "ok"
		default:
			v.Status = "Nothing sent since opgate started"
		}
		for _, c := range notifyCats {
			v.Rows = append(v.Rows, catRow{Key: c.Key, Name: c.Name, Help: c.Help, Opts: segOpts(c.Levels, levelLabels, dev.level(c.Key))})
		}
		d.Devices = append(d.Devices, v)
	}
	return d
}

// notifyAttention adds the overview's items about notifications (devices that stopped or fail, nobody asked).
func (b *Broker) notifyAttention(now time.Time) []attnItem {
	if b.push == nil {
		return nil
	}
	s, err := b.push.prefs.get()
	if err != nil {
		return []attnItem{{Level: "bad", Title: "Notification settings can't be read", Text: "No notifications go out until opgate can read its keychain item. " + short(err.Error(), 200), Link: "/settings"}}
	}
	var out []attnItem
	for _, d := range s.Devices {
		if !d.Gone.IsZero() {
			out = append(out, attnItem{Level: "bad", Title: "Notifications on " + d.Name + " stopped",
				Text: "The browser ended its subscription: open Notifications on that device and turn them on again.", When: clock(now, d.Gone), Link: "/settings"})
			continue
		}
		if st := b.push.prefs.statusOf(d.ID); st.Fails >= failingAfter {
			out = append(out, attnItem{Level: "warn", Title: fmt.Sprintf("Notifications to %s failed %d× in a row", d.Name, st.Fails),
				Text: short(st.Err, 200), When: "last " + clock(now, st.LastFail), Link: "/settings"})
		}
	}
	asks := false
	for _, d := range s.active() {
		asks = asks || d.level("ask") != lvOff
	}
	if !asks {
		out = append(out, attnItem{Level: "bad", Title: "No device gets approval requests",
			Text: "Requests only show on this page. Turn notifications on for a device (Notifications).", Link: "/settings"})
	}
	return out
}

func (b *Broker) logSettings(what string) {
	b.audit.Log(&Request{RequestIn: RequestIn{Kind: "settings", Reason: what}, ID: randomID(6)}, "notify-settings", "", "")
}

// subIn is a browser's push subscription as the page (or the service worker) sends it.
type subIn struct {
	Old      string `json:"old"` // resubscribe: the endpoint it replaces
	Endpoint string `json:"endpoint"`
	P256dh   string `json:"p256dh"`
	Auth     string `json:"auth"`
	Name     string `json:"name"`
	Mobile   bool   `json:"mobile"`
}

func (in *subIn) check() error {
	if len(in.Endpoint) > 1024 || !pushHostAllowed(in.Endpoint) {
		return errors.New("this browser's push service isn't one opgate sends to")
	}
	k, err := decodeB64u(in.P256dh)
	if err == nil {
		_, err = ecdh.P256().NewPublicKey(k)
	}
	if err != nil {
		return errors.New("bad browser key")
	}
	if a, err := decodeB64u(in.Auth); err != nil || len(a) != 16 {
		return errors.New("bad auth secret")
	}
	return nil
}

func cleanName(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	for utf8.RuneCountInString(s) > 40 {
		_, n := utf8.DecodeLastRuneInString(s)
		s = s[:len(s)-n]
	}
	if s == "" {
		s = "Device"
	}
	return s
}

func (b *Broker) settingsRoutes(mux *http.ServeMux) {
	dict := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i+1 < len(kv); i += 2 {
			m[fmt.Sprint(kv[i])] = kv[i+1]
		}
		return m
	}
	page := template.Must(template.New("settings.html").Funcs(template.FuncMap{"dict": dict}).ParseFS(web, "web/settings.html"))
	mux.HandleFunc("GET /settings", func(w http.ResponseWriter, req *http.Request) {
		if b.push == nil {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := page.Execute(w, b.settingsPage(req)); err != nil {
			log.Printf("settings page: %v", err)
		}
	})
	// changes: JSON in, {"status": ...} or {"error": ...} out; all need the unlock
	change := func(path string, f func(req *http.Request, body []byte) (any, error)) {
		mux.HandleFunc("POST "+path, func(w http.ResponseWriter, req *http.Request) {
			if b.push == nil {
				http.NotFound(w, req)
				return
			}
			if b.unlockedUntil(req).IsZero() {
				writeJSONStatus(w, http.StatusForbidden, map[string]string{"error": "locked: unlock with your passkey first"})
				return
			}
			body, _ := io.ReadAll(io.LimitReader(req.Body, 8192))
			v, err := f(req, body)
			writeJSON(w, v, err)
		})
	}
	change("/notify/subscribe", func(_ *http.Request, body []byte) (any, error) {
		var in subIn
		if err := json.Unmarshal(body, &in); err != nil {
			return nil, errors.New("bad request")
		}
		if err := in.check(); err != nil {
			return nil, err
		}
		id, name, renewed := "", cleanName(in.Name), false
		err := b.push.prefs.update(func(s *notifySettings) error {
			for i, d := range s.Devices {
				if d.Endpoint == in.Endpoint { // the same browser again: new keys, keep its settings
					s.Devices[i].P256dh, s.Devices[i].Auth, s.Devices[i].Gone = in.P256dh, in.Auth, time.Time{}
					id, name, renewed = d.ID, d.Name, true
					return nil
				}
			}
			if len(s.Devices) >= maxDevices {
				return fmt.Errorf("already %d devices: remove one first", maxDevices)
			}
			id = randomID(8)
			s.Devices = append(s.Devices, pushDevice{ID: id, Name: name, Mobile: in.Mobile, Added: b.now(),
				Endpoint: in.Endpoint, P256dh: in.P256dh, Auth: in.Auth})
			return nil
		})
		if err != nil {
			return nil, err
		}
		if renewed {
			b.logSettings("notifications renewed on " + name)
		} else {
			b.logSettings("notifications turned on for " + name)
		}
		return map[string]string{"id": id}, nil
	})
	change("/notify/level", func(_ *http.Request, body []byte) (any, error) {
		var in struct{ ID, Cat, Level string }
		if err := json.Unmarshal(body, &in); err != nil {
			return nil, errors.New("bad request")
		}
		c, ok := catByKey(in.Cat)
		if !ok || !slices.Contains(c.Levels, in.Level) {
			return nil, errors.New("unknown setting")
		}
		name := ""
		err := b.push.prefs.update(func(s *notifySettings) error {
			for i, d := range s.Devices {
				if d.ID == in.ID {
					if s.Devices[i].Levels == nil {
						s.Devices[i].Levels = map[string]string{}
					}
					s.Devices[i].Levels[in.Cat] = in.Level
					name = d.Name
					return nil
				}
			}
			return errors.New("no such device")
		})
		if err == nil {
			b.logSettings(fmt.Sprintf("%s on %s: %s", c.Name, name, levelLabels[in.Level]))
		}
		return map[string]string{"status": "saved"}, err
	})
	change("/notify/rename", func(_ *http.Request, body []byte) (any, error) {
		var in struct{ ID, Name string }
		if err := json.Unmarshal(body, &in); err != nil {
			return nil, errors.New("bad request")
		}
		name, old := cleanName(in.Name), ""
		err := b.push.prefs.update(func(s *notifySettings) error {
			for i, d := range s.Devices {
				if d.ID == in.ID {
					old, s.Devices[i].Name = d.Name, name
					return nil
				}
			}
			return errors.New("no such device")
		})
		if err == nil {
			b.logSettings("renamed " + old + " to " + name)
		}
		return map[string]string{"status": "saved"}, err
	})
	change("/notify/remove", func(_ *http.Request, body []byte) (any, error) {
		var in struct{ ID string }
		if err := json.Unmarshal(body, &in); err != nil {
			return nil, errors.New("bad request")
		}
		name := ""
		err := b.push.prefs.update(func(s *notifySettings) error {
			i := slices.IndexFunc(s.Devices, func(d pushDevice) bool { return d.ID == in.ID })
			if i < 0 {
				return errors.New("no such device")
			}
			name = s.Devices[i].Name
			s.Devices = slices.Delete(s.Devices, i, i+1)
			return nil
		})
		if err == nil {
			b.push.prefs.forget(in.ID)
			b.logSettings("notifications removed from " + name)
		}
		return map[string]string{"status": "removed"}, err
	})
	change("/notify/test", func(_ *http.Request, body []byte) (any, error) {
		var in struct{ ID string }
		if err := json.Unmarshal(body, &in); err != nil {
			return nil, errors.New("bad request")
		}
		return map[string]string{"status": "sent"}, b.push.Test(in.ID)
	})
	// The browser renewed its subscription (service worker, pushsubscriptionchange). No unlock (nobody is there),
	// but only for a known subscription: the old endpoint is a capability URL only opgate and that browser know.
	mux.HandleFunc("POST /notify/resubscribe", func(w http.ResponseWriter, req *http.Request) {
		if b.push == nil {
			http.NotFound(w, req)
			return
		}
		var in subIn
		if err := json.NewDecoder(io.LimitReader(req.Body, 8192)).Decode(&in); err != nil || in.Old == "" {
			writeJSON(w, nil, errors.New("bad request"))
			return
		}
		if err := in.check(); err != nil {
			writeJSON(w, nil, err)
			return
		}
		name := ""
		err := b.push.prefs.update(func(s *notifySettings) error {
			for i, d := range s.Devices {
				if d.Endpoint == in.Old {
					s.Devices[i].Endpoint, s.Devices[i].P256dh, s.Devices[i].Auth, s.Devices[i].Gone = in.Endpoint, in.P256dh, in.Auth, time.Time{}
					name = d.Name
					return nil
				}
			}
			return errors.New("unknown subscription")
		})
		if err == nil {
			b.logSettings("subscription renewed by the browser on " + name)
		}
		writeJSON(w, map[string]string{"status": "renewed"}, err)
	})
}
