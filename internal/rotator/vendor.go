package rotator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	githubDefaultBase = "https://api.github.com"
	gitlabAPIVersion  = "/api/v4"
)

// vendorRotator rotates personal access tokens for a provider that has
// a token-rotation API: GitHub fine-grained PATs and GitLab PATs. Both
// share one shape: create a new token with the credential, persist its
// id in spec state, and — on later rotations — revoke the token we
// created previously.
//
// GitLab additionally offers self-rotate (since 16.10): the endpoint
// /personal_access_tokens/self/rotate revokes the authenticating token
// and returns a replacement in one call, so the previous value dies
// immediately rather than living through a grace period. keysec prefers
// it when the token may rotate itself and falls back to create-only
// otherwise.
//
// Revoke-old is deliberately create-only on the first create run: without
// an id we cannot revoke a pre-existing token from its value (neither
// GitHub nor GitLab offers token-by-value revocation), so the old token
// is left to expire naturally.
type vendorRotator struct {
	spec *Spec
	kind string
}

// apiError is a provider HTTP failure that keeps the status code so
// callers can decide whether a different path should be attempted.
type apiError struct {
	url    string
	status string
	code   int
	body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("%s returned %s: %s", e.url, e.status, snippet(e.body, 200))
}

func (v *vendorRotator) Rotate(ctx context.Context, in Input) (Result, error) {
	switch v.kind {
	case KindVendorGithub:
		return v.githubRotate(ctx, in)
	case KindVendorGitlab:
		return v.gitlabRotate(ctx, in)
	default:
		return Result{}, errf("unsupported vendor kind %q", v.kind)
	}
}

// githubRotate creates a fine-grained PAT and, when keysec created a
// previous one (tracked by id), revokes it.
func (v *vendorRotator) githubRotate(ctx context.Context, in Input) (Result, error) {
	if in.Credential == "" {
		return Result{}, errf("github rotation needs a credential")
	}
	base := metaOr(v.spec, "url", githubDefaultBase)
	headerK := "Authorization"
	headerV := "Bearer " + in.Credential
	body, err := v.githubCreateBody(in)
	if err != nil {
		return Result{}, err
	}
	createURL := strings.TrimRight(base, "/") + "/user/personal_access_tokens"
	return v.createAndMaybeRevoke(ctx, createURL, headerK, headerV, body, func(id string) error {
		return v.githubRevoke(ctx, base, headerK, headerV, id)
	})
}

// gitlabRotate prefers GitLab's self-rotate endpoint, which revokes the
// authenticating token and returns a replacement in a single call. When
// the instance refuses self-rotate (403/404/405) it falls back to the
// create-only path, which revokes only tokens keysec created before.
func (v *vendorRotator) gitlabRotate(ctx context.Context, in Input) (Result, error) {
	if in.Credential == "" {
		return Result{}, errf("gitlab rotation needs a credential")
	}
	base := metaOr(v.spec, "url", "")
	if base == "" {
		return Result{}, errf("vendor/gitlab needs a meta url (your GitLab instance)")
	}
	headerK := "PRIVATE-TOKEN"
	headerV := in.Credential

	res, err := v.gitlabSelfRotate(ctx, in, base, headerK, headerV)
	if err == nil {
		return res, nil
	}
	var ae *apiError
	fallback := errors.As(err, &ae) && (ae.code == http.StatusMethodNotAllowed ||
		ae.code == http.StatusNotFound || ae.code == http.StatusForbidden)
	if !fallback {
		return Result{}, err
	}

	body, err := v.gitlabCreateBody(in)
	if err != nil {
		return Result{}, err
	}
	createURL := strings.TrimRight(base, "/") + gitlabAPIVersion + "/personal_access_tokens"
	return v.createAndMaybeRevoke(ctx, createURL, headerK, headerV, body, func(id string) error {
		return v.gitlabRevoke(ctx, base, headerK, headerV, id)
	})
}

// createAndMaybeRevoke performs the create POST and, when keysec created
// a previous token (tracked by id in spec state), retires it.
func (v *vendorRotator) createAndMaybeRevoke(ctx context.Context, createURL, headerK, headerV string, body []byte, revoke func(string) error) (Result, error) {
	resp := newVendorResponse(createURL, headerK, headerV, body)
	id, token, expiresAt, err := doCreate(ctx, resp)
	if err != nil {
		return Result{}, err
	}

	now := time.Now().UTC()
	old := now.Add(parseDurationOrDefault(v.spec.Grace, defaultGrace))
	res := Result{Value: token, ExpiresAt: expiresAt, OldValidUntil: &old, ID: id}

	if prev := v.spec.LastCreatedID; prev != "" && prev != id {
		if err := revoke(prev); err != nil {
			res.Warning = fmt.Sprintf("could not revoke previously created token %s: %v", prev, err)
		}
	}
	return res, nil
}

// vendorResponse carries the raw HTTP call for create.
type vendorResponse struct {
	method, url string
	headerKey   string
	headerVal   string
	body        []byte
}

func newVendorResponse(url, headerKey, headerVal string, body []byte) vendorResponse {
	return vendorResponse{method: http.MethodPost, url: url, headerKey: headerKey, headerVal: headerVal, body: body}
}

// doCreate performs the POST and decodes the token fields from the
// provider's JSON reply.
func doCreate(ctx context.Context, r vendorResponse) (id, token string, expiresAt *time.Time, err error) {
	ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.method, r.url, bytes.NewReader(r.body))
	if err != nil {
		return "", "", nil, errf("create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(r.headerKey, r.headerVal)
	resp, err := (&http.Client{Timeout: defaultTimeout}).Do(req)
	if err != nil {
		return "", "", nil, errf("create request failed: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", "", nil, errf("reading create response: %v", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", nil, &apiError{url: r.url, status: resp.Status, code: resp.StatusCode, body: snippet(string(data), 200)}
	}
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return "", "", nil, errf("create response is not JSON: %v", err)
	}
	id = asString(doc["id"], true)
	token = asString(doc["token"], false)
	if token == "" {
		return "", "", nil, errf("create response has no token")
	}
	if ev, ok := doc["expires_at"]; ok {
		if t, e := expiryFromValue(ev); e == nil {
			u := t.UTC()
			expiresAt = &u
		}
	}
	return id, token, expiresAt, nil
}

// githubCreateBody builds the fine-grained PAT create request.
func (v *vendorRotator) githubCreateBody(in Input) ([]byte, error) {
	now := time.Now().UTC()
	days := atoi(metaOr(v.spec, "expiration_days", "30"))
	if days < 1 {
		days = 30
	}
	if days > 366 {
		days = 366
	}
	params := map[string]any{
		"title":      metaOr(v.spec, "title", keysecDefaultName(in.Key)),
		"expiration": now.AddDate(0, 0, days).Format("2006-01-02"),
	}
	if p := strings.TrimSpace(metaOr(v.spec, "permissions", "")); p != "" {
		var perm map[string]string
		if err := json.Unmarshal([]byte(p), &perm); err != nil {
			return nil, errf("meta permissions must be JSON: %v", err)
		}
		params["permissions"] = perm
	} else if s := strings.TrimSpace(metaOr(v.spec, "scopes", "")); s != "" {
		params["scopes"] = splitCSV(s)
	} else {
		return nil, errf("github rotation needs meta scopes or meta permissions")
	}
	return json.Marshal(params)
}

// githubRevoke deletes a PAT by id. GitHub has no token-by-value
// revocation, so only tokens we created (whose id we stored) can be
// retired this way.
func (v *vendorRotator) githubRevoke(ctx context.Context, base, headerKey, headerVal, id string) error {
	url := strings.TrimRight(base, "/") + "/user/personal_access_tokens/" + id
	return vendorDelete(ctx, url, headerKey, headerVal)
}

// gitlabSelfRotate calls POST /personal_access_tokens/self/rotate. It
// revokes the authenticating token and returns its replacement, so the
// old value dies immediately rather than surviving a grace period.
func (v *vendorRotator) gitlabSelfRotate(ctx context.Context, in Input, base, headerKey, headerVal string) (Result, error) {
	body, err := v.gitlabSelfRotateBody(in)
	if err != nil {
		return Result{}, err
	}
	url := strings.TrimRight(base, "/") + gitlabAPIVersion + "/personal_access_tokens/self/rotate"
	resp := newVendorResponse(url, headerKey, headerVal, body)
	id, token, expiresAt, err := doCreate(ctx, resp)
	if err != nil {
		return Result{}, err
	}
	now := time.Now().UTC()
	return Result{Value: token, ExpiresAt: expiresAt, OldValidUntil: &now, ID: id}, nil
}

// gitlabSelfRotateBody pins the replacement token's expiry to the same
// lifetime meta expiration_days would choose for a fresh token.
func (v *vendorRotator) gitlabSelfRotateBody(in Input) ([]byte, error) {
	now := time.Now().UTC()
	days := atoi(metaOr(v.spec, "expiration_days", "365"))
	if days < 1 {
		days = 365
	}
	if days > 365 {
		days = 365
	}
	params := map[string]any{
		"expires_at": now.AddDate(0, 0, days).Format("2006-01-02"),
	}
	return json.Marshal(params)
}

// gitlabCreateBody builds the GitLab PAT create request.
func (v *vendorRotator) gitlabCreateBody(in Input) ([]byte, error) {
	now := time.Now().UTC()
	days := atoi(metaOr(v.spec, "expiration_days", "365"))
	if days < 1 {
		days = 365
	}
	if days > 365 {
		days = 365
	}
	scopes := splitCSV(metaOr(v.spec, "scopes", "api"))
	params := map[string]any{
		"name":       metaOr(v.spec, "name", keysecDefaultName(in.Key)),
		"scopes":     scopes,
		"expires_at": now.AddDate(0, 0, days).Format("2006-01-02"),
	}
	return json.Marshal(params)
}

// gitlabRevoke deletes a PAT by id.
func (v *vendorRotator) gitlabRevoke(ctx context.Context, base, headerKey, headerVal, id string) error {
	url := strings.TrimRight(base, "/") + gitlabAPIVersion + "/personal_access_tokens/" + id
	return vendorDelete(ctx, url, headerKey, headerVal)
}

func vendorDelete(ctx context.Context, url, headerKey, headerVal string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set(headerKey, headerVal)
	resp, err := (&http.Client{Timeout: defaultTimeout}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 && resp.StatusCode != 204 && resp.StatusCode != 404 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fmt.Errorf("%s returned %s: %s", url, resp.Status, snippet(string(data), 200))
	}
	return nil
}

func keysecDefaultName(key string) string {
	return "keysec-" + strings.ReplaceAll(key, ".", "-") + "-" + time.Now().UTC().Format("20060102")
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func asString(v any, allowZero bool) string {
	switch x := v.(type) {
	case string:
		if x == "" && !allowZero {
			return ""
		}
		return x
	case float64:
		if !allowZero && x == 0 {
			return ""
		}
		return strconv.FormatInt(int64(x), 10)
	default:
		return ""
	}
}
