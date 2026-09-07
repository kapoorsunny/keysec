// Package rotator implements secret rotation providers for keysec.
//
// A Rotator knows how to produce a new value for a secret (and, for
// vendors, how to retire the previous one). It never writes to the
// Keychain itself: rotation is atomic from the caller's point of view
// because providers run first and nothing is persisted until they
// succeed.
package rotator

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kapoorsunny/keysec/internal/key"
)

// Kind identifiers.
const (
	KindGenerate         = "generate"
	KindHTTP             = "http"
	KindScript           = "script"
	KindVendorGithub     = "vendor/github"
	KindVendorGitlab     = "vendor/gitlab"
	KindVendorCloudflare = "vendor/cloudflare"
)

// Kinds lists every rotator kind keysec knows, for help and validation.
var Kinds = []string{KindGenerate, KindHTTP, KindScript, KindVendorGithub, KindVendorGitlab, KindVendorCloudflare}

// maxGenerateLength bounds the generate kind. Without a ceiling a typo
// ("--length 500000000") turns into a multi-gigabyte allocation and
// hundreds of millions of crypto/rand reads; no real secret is longer
// than this, and values over ~2KB lose the argv-free write path.
const maxGenerateLength = 4096

// Input carries everything a provider needs to rotate one secret.
type Input struct {
	Key        string            // friendly key name being rotated
	Value      string            // current secret value
	Credential string            // auth_key resolved value, else Value
	Meta       map[string]string // spec.meta plus per-kind config
}

// Result is a provider's successful answer. Value is the new secret;
// the rest is lifecycle metadata persisted by the caller.
type Result struct {
	Value         string
	ExpiresAt     *time.Time // nil = no known expiry
	OldValidUntil *time.Time // when the previous value may be revoked/culled
	Warning       string     // advisory, surfaced but not fatal
	ID            string     // vendor: id of the created resource (for revoking it later)
	// Revoke retires a previously created provider-side resource once the
	// caller has persisted Value. It must only be called after the new value
	// is safely stored; nil means there is nothing to retire here. Providers
	// that revoke atomically as part of rotation (e.g. GitLab self-rotate)
	// leave it nil.
	Revoke func() error
}

// Rotator is a rotation provider.
type Rotator interface {
	// Rotate produces a new value for the secret. Implementations must
	// not write to the Keychain and must not partially complete: return
	// an error instead of a stale value on any failure.
	Rotate(ctx context.Context, in Input) (Result, error)
}

// Error is a provider failure. Err carries the underlying cause when
// there is one.
type Error struct {
	err  error
	kind string
	msg  string
}

func (e *Error) Error() string {
	if e.err != nil {
		return e.msg + ": " + e.err.Error()
	}
	return e.msg
}

// Unwrap exposes the cause for errors.Is/As.
func (e *Error) Unwrap() error { return e.err }

// errf builds an Error with a formatted message.
func errf(format string, args ...any) *Error {
	return &Error{msg: fmt.Sprintf(format, args...)}
}

// Spec is the persisted, non-secret configuration of a rotator. All
// fields are optional unless stated; the only required field is Kind.
// The state fields (rotated_at, expires_at, old_valid_until,
// spec_updated_at, last_created_id) are written by keysec, not by users.
type Spec struct {
	Kind        string            `json:"kind"`
	Length      int               `json:"length,omitempty"`
	Charset     string            `json:"charset,omitempty"`
	URL         string            `json:"url,omitempty"`
	Method      string            `json:"method,omitempty"`
	Auth        string            `json:"auth,omitempty"`
	AuthKey     string            `json:"auth_key,omitempty"`
	Value       string            `json:"value,omitempty"`
	NewExpires  string            `json:"new_expires,omitempty"`
	Grace       string            `json:"grace,omitempty"`
	Script      string            `json:"script,omitempty"`
	Body        string            `json:"body,omitempty"`
	Interpreter string            `json:"interpreter,omitempty"`
	Timeout     string            `json:"timeout,omitempty"`
	Meta        map[string]string `json:"meta,omitempty"`
	// State (written by keysec).
	RotatedAt     string `json:"rotated_at,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
	OldValidUntil string `json:"old_valid_until,omitempty"`
	LastCreatedID string `json:"last_created_id,omitempty"`
	SpecUpdatedAt string `json:"spec_updated_at,omitempty"`
}

// IsKnownKind reports whether kind is a rotator kind keysec can serve.
func IsKnownKind(kind string) bool {
	for _, k := range Kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// New returns a rotator for the spec's kind.
func New(spec *Spec) (Rotator, error) {
	if spec == nil {
		return nil, fmt.Errorf("rotator: nil spec")
	}
	switch spec.Kind {
	case KindGenerate:
		return &generateRotator{spec: spec}, nil
	case KindHTTP:
		return &httpRotator{spec: spec}, nil
	case KindScript:
		return &scriptRotator{spec: spec}, nil
	case KindVendorGithub:
		return &vendorRotator{spec: spec, kind: KindVendorGithub}, nil
	case KindVendorGitlab:
		return &vendorRotator{spec: spec, kind: KindVendorGitlab}, nil
	case KindVendorCloudflare:
		return &vendorRotator{spec: spec, kind: KindVendorCloudflare}, nil
	default:
		return nil, fmt.Errorf("rotator: unknown kind %q (known: %s)", spec.Kind, strings.Join(Kinds, ", "))
	}
}

// Validate checks a spec without needing a provider. It is used by
// "rotator set" before anything is persisted.
func (s *Spec) Validate() error {
	if !IsKnownKind(s.Kind) {
		return fmt.Errorf("unknown rotator kind %q (known: %s)", s.Kind, strings.Join(Kinds, ", "))
	}
	if s.AuthKey != "" {
		if _, err := key.Parse(s.AuthKey); err != nil {
			return fmt.Errorf("auth_key: %v", err)
		}
	}
	switch s.Kind {
	case KindGenerate:
		// Length is optional: unset means the documented default of 32,
		// applied by the generator. Rejecting 0 here made that default
		// unreachable and refused "rotator set <key> --kind generate".
		if s.Length < 0 {
			return fmt.Errorf("length cannot be negative")
		}
		if s.Length > maxGenerateLength {
			return fmt.Errorf("length must be at most %d", maxGenerateLength)
		}
		if utf8.RuneCountInString(s.Charset) > 256 {
			return fmt.Errorf("charset must be at most 256 characters")
		}
	case KindHTTP:
		if s.URL == "" {
			return fmt.Errorf("http rotator needs a url")
		}
		if err := validateHTTPAuth(s.Auth); err != nil {
			return err
		}
	case KindScript:
		if s.Script == "" && s.Body == "" {
			return fmt.Errorf("script rotator needs a script or a body")
		}
	case KindVendorGithub, KindVendorGitlab, KindVendorCloudflare:
		if u := metaOr(s, "url", ""); u == "" {
			// default base URLs apply; nothing to require.
		}
	}
	if s.Timeout != "" {
		if _, err := ParseDuration(s.Timeout); err != nil {
			return fmt.Errorf("timeout: %v", err)
		}
	}
	if s.Grace != "" {
		if _, err := ParseDuration(s.Grace); err != nil {
			return fmt.Errorf("grace: %v", err)
		}
	}
	return nil
}

// ParseDuration parses a Go-style duration, mirroring time.ParseDuration.
func ParseDuration(s string) (time.Duration, error) {
	return time.ParseDuration(s)
}

// ParseExpiry reads an expiry value in either RFC 3339 form, a bare
// date (YYYY-MM-DD), or seconds since the Unix epoch. It returns a nil
// time when s is empty.
func ParseExpiry(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return &t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		u := t.UTC()
		return &u, nil
	}
	// The whole string must be an integer: a partial match would silently
	// reinterpret e.g. "2030-01-01 12:00" as the year 2030.
	if secs, err := strconv.ParseInt(s, 10, 64); err == nil {
		t := time.Unix(secs, 0).UTC()
		return &t, nil
	}
	return nil, fmt.Errorf("unrecognized expiry %q (want RFC 3339, YYYY-MM-DD, or unix seconds)", s)
}

var metaKeyRe = regexp.MustCompile(`\{meta\.([A-Za-z0-9_.-]+)\}`)
var keyRe = regexp.MustCompile(`\{key\}`)
var valueRe = regexp.MustCompile(`\{value\}`)

// RenderTemplate substitutes {key}, {value} and {meta.<K>} in a string.
// Unknown placeholders (a meta key the input does not carry, or any
// other brace token) are left untouched.
//
// Substitution is literal throughout: a secret is arbitrary text, and
// ReplaceAllString would read a "$1" or "$name" inside it as a capture
// reference and silently drop it. ReplaceAllStringFunc (used for meta)
// already returns its result verbatim.
func RenderTemplate(tpl string, in Input) string {
	out := keyRe.ReplaceAllLiteralString(tpl, in.Key)
	out = valueRe.ReplaceAllLiteralString(out, in.Value)
	return metaKeyRe.ReplaceAllStringFunc(out, func(m string) string {
		match := metaKeyRe.FindStringSubmatch(m)
		if v, ok := in.Meta[match[1]]; ok {
			return v
		}
		return m
	})
}

// EnvMetaName maps a meta key onto an environment variable name:
// upper-cased with anything that is not alphanumeric replaced by _.
func EnvMetaName(k string) string {
	var b strings.Builder
	for _, r := range k {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.ToUpper(b.String())
}

// metaOr returns meta[key] as a defaulted string.
func metaOr(s *Spec, keyVal, def string) string {
	if s.Meta == nil {
		return def
	}
	if v, ok := s.Meta[keyVal]; ok && v != "" {
		return v
	}
	return def
}
