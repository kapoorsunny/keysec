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

func gitlabServer(log *vendorLog) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 0)
		if r.Body != nil {
			b := make([]byte, 1<<16)
			n, _ := r.Body.Read(b)
			body = b[:n]
		}
		log.record(r.Method, r.URL.Path, r.Header.Get("PRIVATE-TOKEN"), body)
		switch {
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
	// Second call is the DELETE of the previously created token.
	if got := log.count(); got != 2 {
		t.Fatalf("calls = %d, want 2 (create + revoke)", got)
	}
	del := log.calls[1]
	if del.method != "DELETE" || del.path != "/user/personal_access_tokens/41" {
		t.Errorf("revoke call = %s %s", del.method, del.path)
	}
	if res.Warning != "" {
		t.Errorf("unexpected warning: %s", res.Warning)
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

func TestVendorGitlabCreateAndRevoke(t *testing.T) {
	var log vendorLog
	srv := gitlabServer(&log)
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
	if log.count() != 2 {
		t.Fatalf("calls = %d, want 2", log.count())
	}
	create, del := log.calls[0], log.calls[1]
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
		if r.Method == http.MethodPost {
			json.NewEncoder(w).Encode(map[string]any{"id": 9, "token": "newtoken"})
			return
		}
		w.WriteHeader(500)
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
	if !strings.Contains(res.Warning, "8") {
		t.Errorf("warning = %q, want the failed revoke mentioned", res.Warning)
	}
}
