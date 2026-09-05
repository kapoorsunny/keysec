package rotator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const defaultGrace = 24 * time.Hour
const defaultTimeout = 30 * time.Second

// httpRotator rotates a secret by calling an authenticated endpoint and
// extracting the new value (and optional expiry) from its JSON reply.
type httpRotator struct {
	spec *Spec
}

func (h *httpRotator) Rotate(ctx context.Context, in Input) (Result, error) {
	spec := h.spec
	if err := validateHTTPAuth(spec.Auth); err != nil {
		return Result{}, errf("bad auth: %v", err)
	}
	method := strings.ToUpper(spec.Method)
	if method == "" {
		method = http.MethodPost
	}
	url := RenderTemplate(spec.URL, in)
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return Result{}, errf("invalid url: %v", err)
	}
	if err := applyHTTPAuth(req, spec.Auth, in.Credential); err != nil {
		return Result{}, err
	}

	timeout := parseDurationOrDefault(spec.Timeout, defaultTimeout)
	if timeout < 0 {
		return Result{}, errf("timeout must be non-negative")
	}
	client := &http.Client{Timeout: timeout}
	resp, err := client.Do(req)
	if err != nil {
		return Result{}, errf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{}, errf("reading response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return Result{}, errf("rotation endpoint returned %s: %s",
			resp.Status, snippet(string(body), 200))
	}

	value, expires, err := extractHTTPValue(body, spec.Value, spec.NewExpires)
	if err != nil {
		return Result{}, err
	}
	if value == "" {
		return Result{}, errf("rotation endpoint did not return a value")
	}

	now := time.Now().UTC()
	grace := parseDurationOrDefault(spec.Grace, defaultGrace)
	old := now.Add(grace)
	return Result{
		Value:         value,
		ExpiresAt:     expires,
		OldValidUntil: &old,
	}, nil
}

// validateHTTPAuth checks the auth spec's shape.
func validateHTTPAuth(auth string) error {
	if auth == "" {
		return nil
	}
	scheme, arg, _ := strings.Cut(auth, ":")
	switch scheme {
	case "bearer":
		return nil
	case "basic":
		if arg == "" {
			return fmt.Errorf("basic auth needs a user ('basic:<user>')")
		}
		return nil
	case "header":
		if arg == "" {
			return fmt.Errorf("header auth needs a name ('header:<Name>')")
		}
		return nil
	case "query":
		if arg == "" {
			return fmt.Errorf("query auth needs a parameter name ('query:<name>')")
		}
		return nil
	default:
		return fmt.Errorf("unknown auth scheme %q (bearer | basic:<user> | header:<Name> | query:<name>)", scheme)
	}
}

// applyHTTPAuth decorates a request with the credential per the auth
// spec. The secret is never part of the spec itself.
func applyHTTPAuth(req *http.Request, auth, credential string) error {
	if auth == "" || credential == "" {
		return nil
	}
	scheme, arg, _ := strings.Cut(auth, ":")
	switch scheme {
	case "bearer":
		req.Header.Set("Authorization", "Bearer "+credential)
	case "basic":
		req.SetBasicAuth(arg, credential)
	case "header":
		req.Header.Set(arg, credential)
	case "query":
		q := req.URL.Query()
		q.Set(arg, credential)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

// extractHTTPValue pulls the new value and, optionally, its expiry from
// a JSON response body by dot-path, falling back to the whole trimmed
// body when no path is configured.
func extractHTTPValue(body []byte, valuePath, expiresPath string) (string, *time.Time, error) {
	var doc any
	if json.Unmarshal(body, &doc) == nil {
		if valuePath != "" {
			v, found := Lookup(doc, valuePath)
			if !found {
				return "", nil, errf("value path %q not found in response", valuePath)
			}
			s, ok := v.(string)
			if !ok {
				return "", nil, errf("value at %q is not a string (%T)", valuePath, v)
			}
			return s, expiryFromAny(doc, expiresPath), nil
		}
		// No value path: try new_expires against the whole doc.
		return string(body), expiryFromAny(doc, expiresPath), nil
	}
	if valuePath == "" {
		return strings.TrimSpace(string(body)), nil, nil
	}
	return "", nil, errf("response is not JSON but a value path %q was configured", valuePath)
}

// expiryFromAny resolves expiresPath against a decoded JSON document.
func expiryFromAny(doc any, path string) *time.Time {
	if path == "" {
		return nil
	}
	v, found := Lookup(doc, path)
	if !found {
		return nil
	}
	t, err := expiryFromValue(v)
	if err != nil {
		return nil
	}
	return &t
}

// expiryFromValue accepts an RFC 3339 string or a number of seconds (or
// milliseconds, detected by magnitude).
func expiryFromValue(v any) (time.Time, error) {
	switch x := v.(type) {
	case string:
		t, err := ParseExpiry(x)
		if err != nil {
			return time.Time{}, err
		}
		if t == nil {
			return time.Time{}, fmt.Errorf("empty expiry")
		}
		return *t, nil
	case float64:
		secs := x
		if secs > 1e12 {
			secs /= 1000.0 // milliseconds
		}
		return time.Unix(int64(secs), 0).UTC(), nil
	case json.Number:
		f, _ := x.Float64()
		return expiryFromValue(f)
	default:
		return time.Time{}, fmt.Errorf("expiry is %T, want string or number", v)
	}
}

// Lookup walks a decoded JSON document following a dot-path such as
// "data.token" or "nested.list.0" (numeric segments index arrays).
func Lookup(doc any, path string) (any, bool) {
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			return nil, false
		}
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			var i int
			if _, err := fmt.Sscanf(seg, "%d", &i); err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

func parseDurationOrDefault(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

func snippet(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return strings.TrimSpace(s[:n]) + "…"
	}
	return strings.TrimSpace(s)
}
