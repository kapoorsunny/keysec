// Package key parses and validates keysec key names.
package key

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ReservedService is the Keychain service every keysec key lives under.
// It doubles as keysec's ownership marker: anything in the Keychain with
// service "keysec" is a keysec secret.
const ReservedService = "keysec"

const maxNameLen = 255

// ReservedSuffix marks companion entries holding rotator specs. A name
// ending in it is a companion (<key>.rotator), never a user key.
const ReservedSuffix = ".rotator"

// ErrInvalid is returned for names that are not valid key names.
var ErrInvalid = errors.New("invalid key name")

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Key is a parsed keysec key. In v0.2 every key maps to one Keychain
// location: the reserved service plus the full name as account. Dots in
// the name are just characters, not coordinates.
type Key struct {
	Name    string // full friendly name, e.g. "gitlab.repo_flay"
	Service string // always ReservedService
	Account string // always equal to Name
}

// Parse validates name and derives the Keychain coordinates. It rejects
// the reserved ".rotator" suffix, which is reserved for companion (rotator
// spec) entries.
func Parse(name string) (Key, error) {
	if len(name) == 0 || len(name) > maxNameLen {
		return Key{}, fmt.Errorf("%w: names must be 1-%d characters", ErrInvalid, maxNameLen)
	}
	if !nameRe.MatchString(name) {
		return Key{}, fmt.Errorf("%w: use letters, digits, dots and dashes (e.g. 'gitlab.repo_flay')", ErrInvalid)
	}
	if strings.Contains(name, "..") || strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") {
		return Key{}, fmt.Errorf("%w: no empty segments (avoid '..' and leading/trailing dots)", ErrInvalid)
	}
	if strings.HasSuffix(name, ReservedSuffix) {
		return Key{}, fmt.Errorf("%w: %q is reserved for rotator companion entries", ErrInvalid, ReservedSuffix)
	}
	return Key{Name: name, Service: ReservedService, Account: name}, nil
}

// ParseServiceAccount derives the Keychain coordinates for a (service,
// account) pair read back from the Keychain's own enumeration. It is the
// inverse of Parse for the keysec service:  let the name be the account and
// validate it. Only service ReservedService lines up with keysec keys.
func ParseServiceAccount(service, account string) (Key, error) {
	if service != ReservedService {
		return Key{}, fmt.Errorf("%w: unexpected service %q", ErrInvalid, service)
	}
	if strings.HasSuffix(account, ReservedSuffix) {
		return Key{}, fmt.Errorf("%w: %q is reserved for rotator companion entries", ErrInvalid, ReservedSuffix)
	}
	return Parse(account)
}

// IsCompanion reports whether account names a rotator companion entry
// (a keysec.<key>.rotator spec). The bare suffix "rotator" does not count:
// companions always end in ".rotator".
func IsCompanion(account string) bool {
	return strings.HasSuffix(account, ReservedSuffix) && len(account) > len(ReservedSuffix)
}

// CompanionName is the account of the companion entry holding the rotator
// spec for key name.
func CompanionName(name string) string { return name + ReservedSuffix }

// ParentName returns the parent key for a companion account. It reports
// ok=false when account is not a companion.
func ParentName(account string) (string, bool) {
	if !IsCompanion(account) {
		return "", false
	}
	return strings.TrimSuffix(account, ReservedSuffix), true
}

// Suggest returns the candidate closest to needle (edit distance <= 2),
// or "" if nothing is close. Comparison is case-insensitive.
func Suggest(needle string, candidates []string) string {
	needle = strings.ToLower(needle)
	best, bestDist := "", 3
	for _, c := range candidates {
		d := distance(needle, strings.ToLower(c))
		if d < bestDist {
			best, bestDist = c, d
		}
	}
	return best
}

func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(cur[j-1]+1, prev[j]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}
