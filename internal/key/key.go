// Package key parses and validates keysec key names.
package key

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// DefaultService is the Keychain service used for keys without a dot.
const DefaultService = "keysec"

const maxNameLen = 255

// ErrInvalid is returned for names that are not valid key names.
var ErrInvalid = errors.New("invalid key name")

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Key is a parsed keysec key: a friendly name plus the Keychain
// coordinates it maps to.
type Key struct {
	Name    string // full name, e.g. "gitlab.repo_flay"
	Service string // Keychain service (part before first dot)
	Account string // Keychain account (part after first dot)
}

// Parse validates name and splits it into Keychain coordinates.
// The part before the first dot becomes the service; the rest is the
// account. Names without a dot go under DefaultService.
func Parse(name string) (Key, error) {
	if len(name) == 0 || len(name) > maxNameLen {
		return Key{}, fmt.Errorf("%w: names must be 1-%d characters", ErrInvalid, maxNameLen)
	}
	if !nameRe.MatchString(name) {
		return Key{}, fmt.Errorf("%w: use letters, digits, dots and dashes (e.g. 'gitlab.repo_flay')", ErrInvalid)
	}
	service, account := DefaultService, name
	if i := strings.IndexByte(name, '.'); i >= 0 {
		service, account = name[:i], name[i+1:]
		if service == "" || account == "" {
			return Key{}, fmt.Errorf("%w: names must not start or end with a dot", ErrInvalid)
		}
		if strings.HasPrefix(account, ".") || strings.Contains(account, "..") ||
			strings.HasSuffix(account, ".") {
			return Key{}, fmt.Errorf("%w: no empty segments (avoid '..' and leading/trailing dots)", ErrInvalid)
		}
	}
	return Key{Name: name, Service: service, Account: account}, nil
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
