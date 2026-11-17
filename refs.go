package main

// Fuzzy references. 1Password's secret references only allow letters, digits, "-", "_", "." and spaces in vault,
// item, section and field names; an item like "Backup bucket (S3)" can otherwise only be read by its ID. opgate
// accepts such names as they are (and with the odd characters left out, in any case): when a reference has
// characters 1Password refuses, or reading it fails, the vault, item and field are looked up by name and read by ID.
//
// Matching per name, first rule that finds exactly one wins: the ID, the exact title, the title ignoring case, the
// title compared on letters and digits only ("Backup bucket S3" = "backup bucket (s3)"). Several matches at the
// same rule are an error naming them: opgate never guesses between two items.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"

	onepassword "github.com/1password/onepassword-sdk-go"
)

type named struct{ ID, Title string }

type namedField struct{ ID, Title, SectionID string }

// refDirectory lists what a reference can name (the service account's SDK, or the owner's op CLI).
type refDirectory interface {
	Vaults(ctx context.Context) ([]named, error)
	Items(ctx context.Context, vaultID string) ([]named, error)
	Fields(ctx context.Context, vaultID, itemID string) ([]namedField, []named, error)
}

// refName is a name reduced to lowercase letters and digits.
func refName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func refCharOK(r rune) bool {
	return r < 128 && (unicode.IsLetter(r) || unicode.IsDigit(r)) || strings.ContainsRune("-_. ", r)
}

// refUnsupported: the reference has a name with characters 1Password's references don't allow.
func refUnsupported(ref string) bool {
	body, _, _ := strings.Cut(strings.TrimPrefix(ref, "op://"), "?")
	for _, r := range body {
		if r != '/' && !refCharOK(r) {
			return true
		}
	}
	return false
}

type refParts struct{ Vault, Item, Section, Field, Query string }

// splitRef: op://vault/item/field or op://vault/item/section/field, optionally ?query.
func splitRef(ref string) (refParts, error) {
	var p refParts
	body, q, _ := strings.Cut(strings.TrimPrefix(ref, "op://"), "?")
	p.Query = q
	s := strings.Split(body, "/")
	switch {
	case !strings.HasPrefix(ref, "op://"):
		return p, fmt.Errorf("not a 1Password reference: %q", ref)
	case len(s) == 3:
		p.Vault, p.Item, p.Field = s[0], s[1], s[2]
	case len(s) == 4:
		p.Vault, p.Item, p.Section, p.Field = s[0], s[1], s[2], s[3]
	default:
		return p, fmt.Errorf("references look like op://<vault>/<item>/[<section>/]<field>, not %q", ref)
	}
	for _, x := range s {
		if x == "" {
			return p, fmt.Errorf("empty name in %q", ref)
		}
	}
	return p, nil
}

// pick finds the one candidate a name means (rules above).
func pick(kind, name, where string, cands []named) (named, error) {
	rules := []func(c named) bool{
		func(c named) bool { return c.ID == name },
		func(c named) bool { return c.Title == name },
		func(c named) bool { return strings.EqualFold(c.Title, name) },
		func(c named) bool { n := refName(name); return n != "" && refName(c.Title) == n },
	}
	for _, match := range rules {
		var hits []named
		for _, c := range cands {
			if match(c) {
				hits = append(hits, c)
			}
		}
		if len(hits) == 1 {
			return hits[0], nil
		}
		if len(hits) > 1 {
			var titles []string
			for _, h := range hits {
				titles = append(titles, fmt.Sprintf("%q (%s)", h.Title, h.ID))
			}
			return named{}, fmt.Errorf("several %ss match %q%s: %s; use the ID", kind, name, where, strings.Join(titles, ", "))
		}
	}
	return named{}, noMatch(fmt.Sprintf("no %s %q%s", kind, name, where))
}

// noMatch: pick found no candidate at all.
type noMatch string

func (e noMatch) Error() string { return string(e) }

// unknownRef: a reference's vault or item isn't there, or its name matches several (checkItem).
type unknownRef string

func (e unknownRef) Error() string { return string(e) }

// checkItem finds a reference's vault and item by name (names only, no values), so a request for an item that isn't
// there is refused before the owner is asked. A name that matches nothing is an unknownRef naming the items whose
// names look alike; errors listing them (1Password unreachable) are returned as they are.
func checkItem(ctx context.Context, dir refDirectory, ref string) error {
	body, _, _ := strings.Cut(strings.TrimPrefix(ref, "op://"), "?")
	vault, rest, _ := strings.Cut(body, "/")
	item, _, _ := strings.Cut(rest, "/")
	if vault == "" || item == "" {
		return unknownRef(fmt.Sprintf("references look like op://<vault>/<item>/[<section>/]<field>, not %q", ref))
	}
	vaults, err := dir.Vaults(ctx)
	if err != nil {
		return err
	}
	v, err := pick("vault", vault, "", vaults)
	if err != nil {
		return unknownRef(err.Error())
	}
	items, err := dir.Items(ctx, v.ID)
	if err != nil {
		return err
	}
	if _, err := pick("item", item, " in "+v.Title, items); err != nil {
		var nm noMatch
		if !errors.As(err, &nm) {
			return unknownRef(err.Error())
		}
		if alike := alikeItems(item, items); len(alike) > 0 {
			return unknownRef(fmt.Sprintf("%v; items with similar names: %s", err, strings.Join(alike, ", ")))
		}
		return unknownRef(fmt.Sprintf("%v, nor one with a similar name", err))
	}
	return nil
}

// alikeItems: titles that share a word of 3 or more letters or digits with name (at most 10).
func alikeItems(name string, items []named) []string {
	words := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	var out []string
	for _, it := range items {
		t := refName(it.Title)
		if slices.ContainsFunc(words, func(w string) bool { return len(w) >= 3 && strings.Contains(t, w) }) {
			out = append(out, fmt.Sprintf("%q", it.Title))
		}
	}
	slices.Sort(out)
	return out[:min(len(out), 10)]
}

func buildRef(parts ...string) string {
	return "op://" + strings.Join(parts, "/")
}

// resolveFuzzy looks up vault and item (and the field when its name needs it) and reads by ID with read.
func resolveFuzzy(ctx context.Context, dir refDirectory, ref string, read func(string) (string, error)) (string, error) {
	p, err := splitRef(ref)
	if err != nil {
		return "", err
	}
	vaults, err := dir.Vaults(ctx)
	if err != nil {
		return "", err
	}
	v, err := pick("vault", p.Vault, "", vaults)
	if err != nil {
		return "", err
	}
	items, err := dir.Items(ctx, v.ID)
	if err != nil {
		return "", err
	}
	it, err := pick("item", p.Item, " in "+v.Title, items)
	if err != nil {
		return "", err
	}
	q := ""
	if p.Query != "" {
		q = "?" + p.Query
	}
	tail := p.Field
	if p.Section != "" {
		tail = p.Section + "/" + p.Field
	}
	var byLabel error
	if !refUnsupported(tail) { // the field as written, on the item's ID: reads only that field
		val, err := read(buildRef(v.ID, it.ID, tail) + q)
		if err == nil {
			return val, nil
		}
		byLabel = err
	}
	fields, sections, err := dir.Fields(ctx, v.ID, it.ID)
	if err != nil {
		return "", err
	}
	where := " in " + it.Title
	sectionID := ""
	if p.Section != "" {
		s, err := pick("section", p.Section, where, sections)
		if err != nil {
			return "", err
		}
		sectionID, where = s.ID, " in "+it.Title+" / "+s.Title
	}
	var cands []named
	for _, f := range fields {
		if sectionID == "" || f.SectionID == sectionID {
			cands = append(cands, named{ID: f.ID, Title: f.Title})
		}
	}
	f, err := pick("field", p.Field, where, cands)
	if err != nil {
		if byLabel != nil {
			return "", fmt.Errorf("%w (%w)", err, byLabel)
		}
		return "", err
	}
	parts := []string{v.ID, it.ID, f.ID}
	if sectionID != "" {
		parts = []string{v.ID, it.ID, sectionID, f.ID}
	}
	return read(buildRef(parts...) + q)
}

// readWithFallback reads ref directly when 1Password can parse it, else (or when that fails) by lookup. A failed
// lookup reports both errors.
func readWithFallback(ctx context.Context, dir refDirectory, ref string, read func(string) (string, error)) (string, error) {
	var direct error
	if !refUnsupported(ref) {
		v, err := read(ref)
		if err == nil || ctx.Err() != nil {
			return v, err
		}
		direct = err
	}
	v, err := resolveFuzzy(ctx, dir, ref, read)
	if err != nil && direct != nil && ctx.Err() == nil {
		return "", fmt.Errorf("%w (lookup ignoring case and punctuation: %w)", direct, err)
	}
	return v, err
}

// ---------- the service account (SDK)

type sdkDirectory struct{ c *onepassword.Client }

func (d sdkDirectory) Vaults(ctx context.Context) ([]named, error) {
	vs, err := d.c.Vaults().List(ctx)
	if err != nil {
		return nil, err
	}
	var out []named
	for _, v := range vs {
		out = append(out, named{v.ID, v.Title})
	}
	return out, nil
}

func (d sdkDirectory) Items(ctx context.Context, vaultID string) ([]named, error) {
	its, err := d.c.Items().List(ctx, vaultID)
	if err != nil {
		return nil, err
	}
	var out []named
	for _, it := range its {
		out = append(out, named{it.ID, it.Title})
	}
	return out, nil
}

func (d sdkDirectory) Fields(ctx context.Context, vaultID, itemID string) ([]namedField, []named, error) {
	it, err := d.c.Items().Get(ctx, vaultID, itemID)
	if err != nil {
		return nil, nil, err
	}
	var fs []namedField
	for _, f := range it.Fields {
		sec := ""
		if f.SectionID != nil {
			sec = *f.SectionID
		}
		fs = append(fs, namedField{f.ID, f.Title, sec})
	}
	var ss []named
	for _, s := range it.Sections {
		ss = append(ss, named{s.ID, s.Title})
	}
	return fs, ss, nil
}

// ---------- the owner's op CLI (Touch ID route)

type cliDirectory struct {
	run func(args ...string) (string, error)
}

func (d cliDirectory) list(args ...string) ([]map[string]any, error) {
	out, err := d.run(append(args, "--format", "json")...)
	if err != nil {
		return nil, err
	}
	var v []map[string]any
	return v, json.Unmarshal([]byte(out), &v)
}

func str(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func (d cliDirectory) Vaults(context.Context) ([]named, error) {
	vs, err := d.list("vault", "list")
	var out []named
	for _, v := range vs {
		out = append(out, named{str(v, "id"), str(v, "name")})
	}
	return out, err
}

func (d cliDirectory) Items(_ context.Context, vaultID string) ([]named, error) {
	its, err := d.list("item", "list", "--vault", vaultID)
	var out []named
	for _, it := range its {
		out = append(out, named{str(it, "id"), str(it, "title")})
	}
	return out, err
}

// Fields reads the item's field and section names (the JSON also has values; only names and IDs are kept).
func (d cliDirectory) Fields(_ context.Context, vaultID, itemID string) ([]namedField, []named, error) {
	out, err := d.run("item", "get", itemID, "--vault", vaultID, "--format", "json")
	if err != nil {
		return nil, nil, err
	}
	var it struct {
		Fields []struct {
			ID      string `json:"id"`
			Label   string `json:"label"`
			Section *struct {
				ID string `json:"id"`
			} `json:"section"`
		} `json:"fields"`
		Sections []struct {
			ID    string `json:"id"`
			Label string `json:"label"`
		} `json:"sections"`
	}
	if err := json.Unmarshal([]byte(out), &it); err != nil {
		return nil, nil, errors.New("op item get: unexpected output")
	}
	var fs []namedField
	for _, f := range it.Fields {
		sec := ""
		if f.Section != nil {
			sec = f.Section.ID
		}
		fs = append(fs, namedField{f.ID, f.Label, sec})
	}
	var ss []named
	for _, s := range it.Sections {
		ss = append(ss, named{s.ID, s.Label})
	}
	return fs, ss, nil
}
