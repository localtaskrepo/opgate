package main

// Web Push (RFC 8030, 8291, 8292): opgate sends its notifications straight to the browsers the owner turned them
// on in (the installed app on the phone, a browser on the Mac). Each message is encrypted for that browser
// (aes128gcm), so the push service (Google's FCM for Chrome) only carries it, and signed with opgate's VAPID key,
// which lives in the keychain like the service account token.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keybase/go-keychain"
)

var b64u = base64.RawURLEncoding

// decodeB64u accepts base64url with or without padding (browsers send it without).
func decodeB64u(s string) ([]byte, error) { return b64u.DecodeString(strings.TrimRight(s, "=")) }

const (
	pushRecordSize = 4096
	maxPushPayload = 3000 // FCM takes 4096 bytes in all; headers and the tag take the rest
)

// encryptPush encrypts one message for a browser (RFC 8291, a single aes128gcm record). asKey and salt are fresh
// random values per message (fixed only in the RFC's test).
func encryptPush(plain, uaPublic, authSecret []byte, asKey *ecdh.PrivateKey, salt []byte) ([]byte, error) {
	if len(plain) > maxPushPayload {
		return nil, fmt.Errorf("push message too long (%d bytes)", len(plain))
	}
	if len(authSecret) != 16 || len(salt) != 16 {
		return nil, errors.New("bad auth secret or salt")
	}
	ua, err := ecdh.P256().NewPublicKey(uaPublic)
	if err != nil {
		return nil, fmt.Errorf("browser key: %w", err)
	}
	secret, err := asKey.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPublic := asKey.PublicKey().Bytes()
	info := append(append([]byte("WebPush: info\x00"), uaPublic...), asPublic...)
	ikm, err := hkdf.Key(sha256.New, secret, authSecret, string(info), 32)
	if err != nil {
		return nil, err
	}
	cek, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: aes128gcm\x00", 16)
	if err != nil {
		return nil, err
	}
	nonce, err := hkdf.Key(sha256.New, ikm, salt, "Content-Encoding: nonce\x00", 12)
	if err != nil {
		return nil, err
	}
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	var out bytes.Buffer
	out.Write(salt)
	out.Write(binary.BigEndian.AppendUint32(nil, pushRecordSize))
	out.WriteByte(byte(len(asPublic)))
	out.Write(asPublic)
	out.Write(gcm.Seal(nil, nonce, append(append([]byte{}, plain...), 0x02), nil)) // 0x02: the last record
	return out.Bytes(), nil
}

// pushOpts are the push service's delivery hints.
type pushOpts struct {
	TTL     time.Duration // how long the push service keeps an undelivered message
	Urgency string        // very-low, low, normal, high
	Topic   string        // an undelivered message with the same topic is replaced (≤ 32 base64url chars)
}

// pushTopic turns a notification tag into a topic.
func pushTopic(tag string) string {
	h := sha256.Sum256([]byte(tag))
	return hex.EncodeToString(h[:16])
}

// errPushGone: the browser dropped the subscription (404/410); sending again is pointless.
var errPushGone = errors.New("the browser ended this subscription")

// pushSender delivers one encrypted message (webPusher; a fake in tests).
type pushSender interface {
	Send(ctx context.Context, d pushDevice, payload []byte, o pushOpts) error
	PublicKey() (string, error)
}

// webPusher signs (VAPID) and sends messages. Its key is created on first use and kept in the keychain.
type webPusher struct {
	blobs   blobStore
	client  *http.Client
	subject string // VAPID "sub": how the push service can reach the sender (the page's URL)

	mu  sync.Mutex
	key *ecdsa.PrivateKey
}

const vapidBlob = "web-push-vapid"

func (p *webPusher) signingKey() (*ecdsa.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key != nil {
		return p.key, nil
	}
	raw, err := p.blobs.Load(vapidBlob)
	if err != nil {
		return nil, fmt.Errorf("VAPID key: %w", err)
	}
	if raw != nil {
		k, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
		if err != nil {
			return nil, fmt.Errorf("VAPID key in the keychain: %w", err)
		}
		p.key = k
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	b, _ := k.Bytes()
	if err := p.blobs.Save(vapidBlob, b); err != nil {
		return nil, fmt.Errorf("storing the VAPID key: %w", err)
	}
	p.key = k
	return k, nil
}

// PublicKey is the application server key browsers subscribe with (base64url, uncompressed point).
func (p *webPusher) PublicKey() (string, error) {
	k, err := p.signingKey()
	if err != nil {
		return "", err
	}
	b, err := k.PublicKey.Bytes()
	if err != nil {
		return "", err
	}
	return b64u.EncodeToString(b), nil
}

// vapidHeader is the Authorization header for one push service (RFC 8292).
func vapidHeader(k *ecdsa.PrivateKey, endpoint, subject string, now time.Time) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	claims, _ := json.Marshal(map[string]any{"aud": u.Scheme + "://" + u.Host, "exp": now.Add(12 * time.Hour).Unix(), "sub": subject})
	signing := b64u.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." + b64u.EncodeToString(claims)
	h := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, k, h[:])
	if err != nil {
		return "", err
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	pub, err := k.PublicKey.Bytes()
	if err != nil {
		return "", err
	}
	return "vapid t=" + signing + "." + b64u.EncodeToString(sig) + ", k=" + b64u.EncodeToString(pub), nil
}

func (p *webPusher) Send(ctx context.Context, d pushDevice, payload []byte, o pushOpts) error {
	k, err := p.signingKey()
	if err != nil {
		return err
	}
	ua, err := decodeB64u(d.P256dh)
	if err != nil {
		return fmt.Errorf("browser key: %w", err)
	}
	auth, err := decodeB64u(d.Auth)
	if err != nil {
		return fmt.Errorf("auth secret: %w", err)
	}
	asKey, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	salt := make([]byte, 16)
	rand.Read(salt)
	body, err := encryptPush(payload, ua, auth, asKey, salt)
	if err != nil {
		return err
	}
	authz, err := vapidHeader(k, d.Endpoint, p.subject, time.Now())
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", d.Endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	ttl := max(int(o.TTL/time.Second), 0)
	req.Header.Set("TTL", strconv.Itoa(ttl))
	req.Header.Set("Content-Encoding", "aes128gcm")
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Authorization", authz)
	if o.Urgency != "" {
		req.Header.Set("Urgency", o.Urgency)
	}
	if o.Topic != "" {
		req.Header.Set("Topic", o.Topic)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return errPushGone
	case resp.StatusCode >= 300:
		return fmt.Errorf("push service: %s %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	return nil
}

// pushHosts are the push services browsers use; subscriptions pointing anywhere else are refused (opgate must not
// post to whatever URL a page hands it).
func pushHostAllowed(endpoint string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return false
	}
	h := strings.ToLower(u.Hostname())
	switch {
	case h == "fcm.googleapis.com", h == "updates.push.services.mozilla.com":
		return true
	case strings.HasSuffix(h, ".push.apple.com"), strings.HasSuffix(h, ".notify.windows.com"):
		return true
	}
	return false
}

// blobStore keeps small private values that agents must neither read nor change: the VAPID key and the
// notification settings (an agent that could edit them could silence the notices about its own key uses).
type blobStore interface {
	Load(name string) ([]byte, error) // nil, nil: not stored yet
	Save(name string, b []byte) error
}

// keychainBlobs stores them as generic passwords created by opgate (only this binary reads them without a dialog).
type keychainBlobs struct{}

func (keychainBlobs) Load(name string) ([]byte, error) { return kcStore.load(name) }

func (keychainBlobs) Save(name string, b []byte) error { return kcStore.save(name, b) }

func keychainLoad(name string) ([]byte, error) {
	q := keychain.NewItem()
	q.SetSecClass(keychain.SecClassGenericPassword)
	q.SetService(appID)
	q.SetAccount(name)
	q.SetMatchLimit(keychain.MatchLimitOne)
	q.SetReturnData(true)
	res, err := keychain.QueryItem(q)
	if err != nil {
		return nil, fmt.Errorf("keychain: %w", err)
	}
	if len(res) == 0 {
		return nil, nil
	}
	return res[0].Data, nil
}

func keychainSave(name string, b []byte) error {
	it := keychain.NewGenericPassword(appID, name, "opgate "+name, b, "")
	it.SetSynchronizable(keychain.SynchronizableNo)
	it.SetAccessible(keychain.AccessibleAfterFirstUnlockThisDeviceOnly)
	err := keychain.AddItem(it)
	if errors.Is(err, keychain.ErrorDuplicateItem) {
		q := keychain.NewItem()
		q.SetSecClass(keychain.SecClassGenericPassword)
		q.SetService(appID)
		q.SetAccount(name)
		u := keychain.NewItem()
		u.SetData(b)
		err = keychain.UpdateItem(q, u)
	}
	if err != nil {
		return fmt.Errorf("keychain: %w", err)
	}
	return nil
}
