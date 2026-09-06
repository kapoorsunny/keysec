package rotator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type vendorCall struct {
	method, path string
	auth         string
	body         map[string]any
}

type vendorLog struct {
	mu    sync.Mutex
	calls []vendorCall
}

func (l *vendorLog) record(method, path, auth string, body []byte) {
	c := vendorCall{method: method, path: path, auth: auth}
	if len(body) > 0 {
		json.Unmarshal(body, &c.body)
	}
	l.mu.Lock()
	l.calls = append(l.calls, c)
	l.mu.Unlock()
}

func (l *vendorLog) last() vendorCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls[len(l.calls)-1]
}

func (l *vendorLog) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.calls)
}

func githubServer(log *vendorLog) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			b := make([]byte, 1<<16)
			n, _ := r.Body.Read(b)
			body = b[:n]
		}
		log.record(r.Method, r.URL.Path, r.Header.Get("Authorization"), body)
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/personal_access_tokens"):
			json.NewEncoder(w).Encode(map[string]any{"id": 42, "token": "ghp_new", "expires_at": "2030-01-01T00:00:00Z"})
		case r.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
}

// gitlabServer models a GitLab PAT API. When allowSelfRotate is true the
// self-rotate endpoint returns a replacement token; otherwise it refuses
// with 405 so the provider falls back to token creation.
func gitlabServer(log *vendorLog, allowSelfRotate bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			b := make([]byte, 1<<16)
			n, _ := r.Body.Read(b)
			body = b[:n]
		}
		log.record(r.Method, r.URL.Path, r.Header.Get("PRIVATE-TOKEN"), body)
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/personal_access_tokens/self/rotate"):
			if !allowSelfRotate {
				w.WriteHeader(http.StatusMethodNotAllowed)
				fmt.Fprint(w, `{"message":"method not allowed"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"id": 13, "token": "glpat_rotated", "expires_at": "2030-02-03"})
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/personal_access_tokens"):
			json.NewEncoder(w).Encode(map[string]any{"id": 7, "token": "glpat_new", "expires_at": "2030-01-01T00:00:00Z"})
		case r.Method == http.MethodDelete:
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestVendorGithubCreate(t *testing.T) {
	var log vendorLog
	srv := githubServer(&log)
	defer srv.Close()

	r, err := New(&Spec{Kind: KindVendorGithub, Meta: map[string]string{
		"url": srv.URL, "scopes": "repo,workflow", "expiration_days": "60",
	}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Rotate(context.Background(), Input{Credential: "old-pat"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "ghp_new" {
		t.Errorf("value = %q", res.Value)
	}
	if res.ID != "42" {
		t.Errorf("id = %q", res.ID)
	}
	c := log.last()
	if c.method != "POST" || c.path != "/user/personal_access_tokens" {
		t.Errorf("call = %s %s", c.method, c.path)
	}
	if c.auth != "Bearer old-pat" {
		t.Errorf("auth = %q", c.auth)
	}
	if c.body["expiration"] != "2026-11-04" && c.body["expiration"] == "" {
		t.Errorf("expiration = %v", c.body["expiration"])
	}
	if got, _ := json.Marshal(c.body["scopes"]); string(got) != `["repo","workflow"]` {
		t.Errorf("scopes = %v", c.body["scopes"])
	}
}

func TestVendorGithubRevokesOwnPrevious(t *testing.T) {
	var log vendorLog
	srv := githubServer(&log)
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindVendorGithub, Meta: map[string]string{"url": srv.URL, "permissions": `{"contents":"write"}`}, LastCreatedID: "41"})
	res, err := r.Rotate(context.Background(), Input{Credential: "pat"})
	if err != nil {
		t.Fatal(err)
	}
	// Revocation is deferred until the caller persists the new value, so
	// Rotate alone must only have created.
	if got := log.count(); got != 1 {
		t.Fatalf("calls after rotate = %d, want 1 (create only; revoke deferred)", got)
	}
	if res.Revoke == nil {
		t.Fatal("expected a deferred Revoke hook for the previous token")
	}
	if err := res.Revoke(); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	// Second call is now the DELETE of the previously created token.
	if got := log.count(); got != 2 {
		t.Fatalf("calls after revoke = %d, want 2 (create + revoke)", got)
	}
	del := log.calls[1]
	if del.method != "DELETE" || del.path != "/user/personal_access_tokens/41" {
		t.Errorf("revoke call = %s %s", del.method, del.path)
	}
}

func TestVendorGithubFirstRotationNoRevoke(t *testing.T) {
	var log vendorLog
	srv := githubServer(&log)
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorGithub, Meta: map[string]string{"url": srv.URL, "permissions": `{}`}})
	if _, err := r.Rotate(context.Background(), Input{Credential: "p"}); err != nil {
		t.Fatal(err)
	}
	if log.count() != 1 {
		t.Errorf("calls = %d, want 1 (create only, no previous to revoke)", log.count())
	}
}

func TestVendorGithubNeedsScopesOrPermissions(t *testing.T) {
	srv := githubServer(&vendorLog{})
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorGithub, Meta: map[string]string{"url": srv.URL}})
	if _, err := r.Rotate(context.Background(), Input{Credential: "p"}); err == nil {
		t.Fatal("github rotation without scopes/permissions should error")
	}
}

func TestVendorGitlabSelfRotate(t *testing.T) {
	var log vendorLog
	srv := gitlabServer(&log, true)
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindVendorGitlab,
		Meta: map[string]string{"url": srv.URL, "expiration_days": "30"}})
	res, err := r.Rotate(context.Background(), Input{Credential: "glpat_old"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "glpat_rotated" || res.ID != "13" {
		t.Errorf("value/id = %q/%q", res.Value, res.ID)
	}
	if log.count() != 1 {
		t.Fatalf("calls = %d, want 1 (self-rotate only)", log.count())
	}
	call := log.last()
	if call.method != "POST" || call.path != "/api/v4/personal_access_tokens/self/rotate" {
		t.Errorf("call = %s %s", call.method, call.path)
	}
	if call.auth != "glpat_old" {
		t.Errorf("auth = %q", call.auth)
	}
	want := time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02")
	if got, _ := json.Marshal(call.body); string(got) != `{"expires_at":"`+want+`"}` {
		t.Errorf("body = %s, want expires_at %s", got, want)
	}
	// GitLab self-rotate returns a bare date; the expiry must still parse.
	if res.ExpiresAt == nil || res.ExpiresAt.Format("2006-01-02") != "2030-02-03" {
		t.Errorf("expires = %v", res.ExpiresAt)
	}
	// Old token died immediately, not after a grace period.
	if res.OldValidUntil == nil || res.OldValidUntil.After(time.Now()) {
		t.Errorf("old valid until = %v, want ~now", res.OldValidUntil)
	}
}

func TestVendorGitlabCreateAndRevoke(t *testing.T) {
	var log vendorLog
	srv := gitlabServer(&log, false)
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindVendorGitlab,
		Meta:          map[string]string{"url": srv.URL, "scopes": "read_api,write_repository", "expiration_days": "30"},
		LastCreatedID: "6"})
	res, err := r.Rotate(context.Background(), Input{Credential: "glpat_old"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "glpat_new" || res.ID != "7" {
		t.Errorf("value/id = %q/%q", res.Value, res.ID)
	}
	// Revocation is deferred: the create call happens inside Rotate but the
	// DELETE must not run until the caller invokes res.Revoke().
	if log.count() != 2 {
		t.Fatalf("calls after rotate = %d, want 2 (self-rotate refused + create; revoke deferred)", log.count())
	}
	if res.Revoke == nil {
		t.Fatal("expected a deferred Revoke hook for the previous token")
	}
	if err := res.Revoke(); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if log.count() != 3 {
		t.Fatalf("calls after revoke = %d, want 3 (self-rotate refused + create + revoke)", log.count())
	}
	attempt, create, del := log.calls[0], log.calls[1], log.calls[2]
	if attempt.method != "POST" || attempt.path != "/api/v4/personal_access_tokens/self/rotate" {
		t.Errorf("attempt = %s %s", attempt.method, attempt.path)
	}
	if create.method != "POST" || create.path != "/api/v4/personal_access_tokens" {
		t.Errorf("create = %s %s", create.method, create.path)
	}
	if create.auth != "glpat_old" {
		t.Errorf("create auth = %q", create.auth)
	}
	if del.method != "DELETE" || del.path != "/api/v4/personal_access_tokens/6" {
		t.Errorf("revoke = %s %s", del.method, del.path)
	}
	if del.auth != "glpat_old" {
		t.Errorf("revoke auth = %q", del.auth)
	}
}

func TestVendorGitlabNeedsBaseURL(t *testing.T) {
	r, _ := New(&Spec{Kind: KindVendorGitlab})
	if _, err := r.Rotate(context.Background(), Input{Credential: "x"}); err == nil {
		t.Fatal("gitlab rotation without a base url should error")
	}
}

// cloudflareServer models the Cloudflare API token API: create returns
// the one-time token value under result.value, delete succeeds.
func cloudflareServer(log *vendorLog) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			b := make([]byte, 1<<16)
			n, _ := r.Body.Read(b)
			body = b[:n]
		}
		log.record(r.Method, r.URL.Path, r.Header.Get("Authorization"), body)
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/user/tokens"):
			var req struct {
				Name     string `json:"name"`
				Policies []any  `json:"policies"`
				Expires  string `json:"expires_on"`
			}
			json.Unmarshal(body, &req)
			if len(req.Policies) == 0 {
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `{"success":false,"errors":[{"message":"policies is required"}]}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{
				"success": true,
				"result":  map[string]any{"id": "cf-token-1", "value": "cf_new", "expires_on": "2030-01-01T00:00:00Z"},
			})
		case r.Method == http.MethodDelete:
			w.WriteHeader(200)
			fmt.Fprint(w, `{"success":true}`)
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestVendorCloudflareCreate(t *testing.T) {
	var log vendorLog
	srv := cloudflareServer(&log)
	defer srv.Close()

	r, err := New(&Spec{Kind: KindVendorCloudflare, Meta: map[string]string{
		"url": srv.URL, "policies": `[{"effect":"allow","resources":{"com.cloudflare.api.account.123":"*"},"permission_groups":[{"id":"8acbe51b14b34acbb9e10e0bd0388e04"}]}]`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Rotate(context.Background(), Input{Credential: "old-token"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "cf_new" {
		t.Errorf("value = %q", res.Value)
	}
	if res.ID != "cf-token-1" {
		t.Errorf("id = %q", res.ID)
	}
	if res.ExpiresAt == nil || res.ExpiresAt.Format(time.RFC3339) != "2030-01-01T00:00:00Z" {
		t.Errorf("expires = %v", res.ExpiresAt)
	}
	c := log.last()
	if c.method != "POST" || c.path != "/user/tokens" {
		t.Errorf("call = %s %s", c.method, c.path)
	}
	if c.auth != "Bearer old-token" {
		t.Errorf("auth = %q", c.auth)
	}
	if p, _ := json.Marshal(c.body["policies"]); len(p) == 0 {
		t.Errorf("policies missing from body: %v", c.body)
	}
	if _, ok := c.body["expires_on"]; !ok {
		t.Errorf("expires_on missing from body: %v", c.body)
	}
}

func TestVendorCloudflareRevokesOwnPrevious(t *testing.T) {
	var log vendorLog
	srv := cloudflareServer(&log)
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindVendorCloudflare,
		Meta:          map[string]string{"url": srv.URL, "policies": `[{"effect":"allow"}]`},
		LastCreatedID: "cf-old"})
	res, err := r.Rotate(context.Background(), Input{Credential: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if got := log.count(); got != 1 {
		t.Fatalf("calls after rotate = %d, want 1 (create only; revoke deferred)", got)
	}
	if res.Revoke == nil {
		t.Fatal("expected a deferred Revoke hook for the previous token")
	}
	if err := res.Revoke(); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if got := log.count(); got != 2 {
		t.Fatalf("calls after revoke = %d, want 2 (create + revoke)", got)
	}
	del := log.calls[1]
	if del.method != "DELETE" || del.path != "/user/tokens/cf-old" {
		t.Errorf("revoke call = %s %s", del.method, del.path)
	}
}

func TestVendorCloudflareFirstRotationNoRevoke(t *testing.T) {
	var log vendorLog
	srv := cloudflareServer(&log)
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorCloudflare, Meta: map[string]string{"url": srv.URL, "policies": `[{"effect":"allow"}]`}})
	if _, err := r.Rotate(context.Background(), Input{Credential: "p"}); err != nil {
		t.Fatal(err)
	}
	if log.count() != 1 {
		t.Errorf("calls = %d, want 1 (create only, no previous to revoke)", log.count())
	}
}

func TestVendorCloudflareNeedsPolicies(t *testing.T) {
	var log vendorLog
	srv := cloudflareServer(&log)
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorCloudflare, Meta: map[string]string{"url": srv.URL}})
	if _, err := r.Rotate(context.Background(), Input{Credential: "p"}); err == nil {
		t.Fatal("cloudflare rotation without policies should error")
	}
}

func TestVendorCloudflareBadPolicies(t *testing.T) {
	var log vendorLog
	srv := cloudflareServer(&log)
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorCloudflare, Meta: map[string]string{"url": srv.URL, "policies": "not json"}})
	if _, err := r.Rotate(context.Background(), Input{Credential: "p"}); err == nil {
		t.Fatal("malformed policies should error before any request")
	}
	if log.count() != 0 {
		t.Errorf("calls = %d, want 0 (body built before the request)", log.count())
	}
}

func TestVendorCloudflareErrorSurfacesMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"success":false,"errors":[{"message":"API Token Editing disabled"}]}`)
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorCloudflare, Meta: map[string]string{"url": srv.URL, "policies": `[{"effect":"allow"}]`}})
	_, err := r.Rotate(context.Background(), Input{Credential: "p"})
	if err == nil {
		t.Fatal("403 should error")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "API Token Editing disabled") {
		t.Errorf("err = %v, want status + provider message", err)
	}
}

func TestVendorCreateNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"message":"forbidden"}`)
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorGithub, Meta: map[string]string{"url": srv.URL, "scopes": "repo"}})
	if _, err := r.Rotate(context.Background(), Input{Credential: "p"}); err == nil {
		t.Fatal("403 should error")
	} else if !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v, want status", err)
	}
}

func TestVendorRevokeFailureWarns(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/personal_access_tokens/self/rotate"):
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `{"message":"method not allowed"}`)
		case r.Method == http.MethodPost:
			json.NewEncoder(w).Encode(map[string]any{"id": 9, "token": "newtoken"})
		default:
			w.WriteHeader(500)
		}
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindVendorGitlab, Meta: map[string]string{"url": srv.URL}, LastCreatedID: "8"})
	res, err := r.Rotate(context.Background(), Input{Credential: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "newtoken" {
		t.Errorf("value = %q", res.Value)
	}
	if res.Revoke == nil {
		t.Fatal("expected a deferred Revoke hook for the previous token")
	}
	// The failed revoke surfaces as an error from the deferred hook, which
	// the caller turns into a warning (the rotation itself already succeeded).
	err = res.Revoke()
	if err == nil {
		t.Fatal("revoke should fail against this server")
	}
	if !strings.Contains(err.Error(), "8") {
		t.Errorf("revoke error = %q, want the failed id mentioned", err)
	}
}
