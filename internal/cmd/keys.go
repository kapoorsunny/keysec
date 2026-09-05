package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"repo.flay.ai/root/keysec/internal/key"
	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/rotator"
)

// listedKey is one enumerated key with its rotator kind resolved.
type listedKey struct {
	name    string
	saved   time.Time // zero when the keychain reports no timestamp
	rotates string    // "" when the key has no rotator
	specErr bool      // a .rotator companion exists but could not be read
}

// listedKeys enumerates the Keychain and joins each key with its rotator
// companion, dropping companions and entries that are not keysec keys.
// Keychain order is unspecified, so the result is sorted by name.
func (a *App) listedKeys(ctx context.Context) ([]listedKey, error) {
	entries, err := a.enum.List(ctx)
	if err != nil {
		return nil, a.enumError(err)
	}
	out := make([]listedKey, 0, len(entries))
	for _, e := range entries {
		if key.IsCompanion(e.Account) {
			continue
		}
		if _, err := key.ParseServiceAccount(e.Service, e.Account); err != nil {
			continue
		}
		lk := listedKey{name: e.Account, saved: e.Modified}
		spec, hasSpec, serr := a.loadSpec(ctx, e.Account)
		switch {
		case serr != nil:
			// A companion exists but is corrupt or unreadable. Mark it so
			// sweeps surface the problem instead of treating the key as one
			// without a rotator (which would silently skip rotation).
			lk.specErr = true
		case hasSpec:
			lk.rotates = spec.Kind
		}
		out = append(out, lk)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// loadSpec reads the rotator spec for name from its <name>.rotator
// companion. ok=false means none is configured.
func (a *App) loadSpec(ctx context.Context, name string) (*rotator.Spec, bool, error) {
	raw, err := a.store.Get(ctx, key.ReservedService, key.CompanionName(name))
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, false, nil
		}
		return nil, false, err
	}
	var s rotator.Spec
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		return nil, true, errors.New("rotator spec for '" + name + "' is corrupted: " + err.Error())
	}
	return &s, true, nil
}

// saveSpec persists the rotator spec for name at the <name>.rotator
// companion entry.
func (a *App) saveSpec(ctx context.Context, name string, s *rotator.Spec) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return a.store.Put(ctx, key.ReservedService, key.CompanionName(name), string(b))
}

// day formats a time as YYYY-MM-DD, or "" for a zero time.
func day(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006-01-02")
}

// strPtr returns a pointer to s, or nil for an empty string, for
// optional JSON fields.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nowStamp is the current time in UTC RFC 3339 form, used for the
// state timestamps keysec writes back into a rotator spec.
func nowStamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// plural returns "" for 1 and "s" otherwise.
func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
