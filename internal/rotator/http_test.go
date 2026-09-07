package rotator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPBearerValuePath(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"token": "newsecret"}})
	}))
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL + "/rotate", Auth: "bearer",
		Value: "data.token", NewExpires: "data.token"})
	res, err := r.Rotate(context.Background(), Input{Key: "k", Value: "old", Credential: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/rotate" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer tok" {
		t.Errorf("Authorization = %q", gotAuth)
	}
	if res.Value != "newsecret" {
		t.Errorf("value = %q", res.Value)
	}
}

func TestHTTPBasicAndTemplates(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{"token": "T1"}`)
	}))
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL + "/{key}", Auth: "basic:alice", Value: "token"})
	res, err := r.Rotate(context.Background(), Input{Key: "k", Value: "old", Credential: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(gotAuth, "Basic ") {
		t.Errorf("auth = %q, want Basic scheme", gotAuth)
	}
	if res.Value != "T1" {
		t.Errorf("value = %q", res.Value)
	}
}

func TestHTTPQueryAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("token"); got != "cred" {
			t.Errorf("query token = %q", got)
		}
		fmt.Fprint(w, `{"value":"T"}`)
	}))
	defer srv.Close()

	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL, Auth: "query:token", Method: "GET", Value: "value"})
	res, err := r.Rotate(context.Background(), Input{Credential: "cred"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "T" {
		t.Errorf("value = %q", res.Value)
	}
}

func TestHTTPNonJSONFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\n  svc-rek   \n")
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL})
	res, err := r.Rotate(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Value != "svc-rek" {
		t.Errorf("value = %q", res.Value)
	}
}

func TestHTTPExpiryEpochSecondsAndMillis(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
	}{
		{`{"e": 1893456000, "token": "x"}`, "2030-01-01"},
		{`{"e": 1893456000000, "token": "x"}`, "2030-01-01"},
		{`{"e": "2030-01-01T00:00:00Z", "token": "x"}`, "2030-01-01"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, tc.raw)
		}))
		r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL, Value: "token", NewExpires: "e"})
		res, err := r.Rotate(context.Background(), Input{})
		srv.Close()
		if err != nil {
			t.Fatalf("%s: %v", tc.raw, err)
		}
		if res.ExpiresAt == nil || res.ExpiresAt.Format("2006-01-02") != tc.want {
			t.Errorf("%s: expiresAt = %v, want %s", tc.raw, res.ExpiresAt, tc.want)
		}
		if res.OldValidUntil == nil {
			t.Error("OldValidUntil should default to now+grace")
		}
	}
}

func TestHTTPNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		fmt.Fprint(w, `{"message":"bad credentials"} full-message-here`)
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL})
	_, err := r.Rotate(context.Background(), Input{Credential: "x"})
	if err == nil {
		t.Fatal("expected error for 401")
	}
	if !strings.Contains(err.Error(), "401") || !strings.Contains(err.Error(), "bad credentials") {
		t.Errorf("err = %v, want status and body snippet", err)
	}
}

func TestHTTPMissingValuePath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"a": 1}`)
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL, Value: "b"})
	if _, err := r.Rotate(context.Background(), Input{}); err == nil {
		t.Fatal("missing value path should error")
	}
}

func TestHTTPJSONBodyWithoutPathIsTrimmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "\n  \"a-token\"  \n")
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL})
	res, err := r.Rotate(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	// The whole-body fallback is the JSON string as written (quotes kept),
	// minus surrounding whitespace.
	if res.Value != `"a-token"` {
		t.Errorf("value = %q, want the trimmed body", res.Value)
	}
}

func TestHTTPValuePathNotString(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"v": 42}`)
	}))
	defer srv.Close()
	r, _ := New(&Spec{Kind: KindHTTP, URL: srv.URL, Value: "v"})
	if _, err := r.Rotate(context.Background(), Input{}); err == nil {
		t.Fatal("numeric value should error")
	}
}

// TestHTTPSendsBody: --body is accepted, stored and documented for the
// http kind, but the request used to be built with a nil body.
func TestHTTPSendsBody(t *testing.T) {
	var gotBody, gotType string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody, gotType = string(b), r.Header.Get("Content-Type")
		w.Write([]byte(`{"token":"new-value"}`))
	}))
	defer srv.Close()
	r, err := New(&Spec{Kind: KindHTTP, URL: srv.URL, Value: "token",
		Body: `{"key":"{key}","old":"{value}"}`})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Rotate(context.Background(), Input{Key: "k", Value: "old-secret"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res.Value != "new-value" {
		t.Errorf("value = %q", res.Value)
	}
	if gotBody != `{"key":"k","old":"old-secret"}` {
		t.Errorf("body = %q", gotBody)
	}
	if gotType != "application/json" {
		t.Errorf("content-type = %q", gotType)
	}
}
