package gitcred

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/kapoorsunny/keysec/internal/keychain"
)

type fakeStore struct {
	m      map[string]string
	getErr error
	delErr error
}

func keyOf(service, account string) string { return service + "\x00" + account }

func (f *fakeStore) Put(ctx context.Context, service, account, value string) error {
	f.m[keyOf(service, account)] = value
	return nil
}
func (f *fakeStore) Get(ctx context.Context, service, account string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	v, ok := f.m[keyOf(service, account)]
	if !ok {
		return "", keychain.ErrNotFound
	}
	return v, nil
}
func (f *fakeStore) Delete(ctx context.Context, service, account string) error {
	if f.delErr != nil {
		return f.delErr
	}
	delete(f.m, keyOf(service, account))
	return nil
}
func (f *fakeStore) Has(ctx context.Context, service, account string) (bool, error) {
	_, ok := f.m[keyOf(service, account)]
	return ok, nil
}

func credInput(protocol, host, path, user, pass string) string {
	var b strings.Builder
	if protocol != "" {
		b.WriteString("protocol=" + protocol + "\n")
	}
	if host != "" {
		b.WriteString("host=" + host + "\n")
	}
	if path != "" {
		b.WriteString("path=" + percentEncode(path) + "\n")
	}
	if user != "" {
		b.WriteString("username=" + user + "\n")
	}
	if pass != "" {
		b.WriteString("password=" + percentEncode(pass) + "\n")
	}
	return b.String()
}

func newShim(store *fakeStore) *Shim {
	return New(store)
}

func TestApproveStoresToken(t *testing.T) {
	s := newShim(&fakeStore{m: map[string]string{}})
	err := s.Run(context.Background(), "approve",
		strings.NewReader(credInput("https", "gitlab.example.com", "/acme/site.git", "oauth2", "tok-1")),
		io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if want := "tok-1"; s.store.(*fakeStore).m[keyOf("keysec", "git.gitlab.example.com.acme.site")] != want {
		t.Errorf("stored = %v, want token under keysec/git.gitlab.example.com.acme.site", s.store.(*fakeStore).m)
	}
}

func TestStoreAliasMeansApprove(t *testing.T) {
	s := newShim(&fakeStore{m: map[string]string{}})
	err := s.Run(context.Background(), "store",
		strings.NewReader(credInput("https", "example.com", "", "u", "tok-2")),
		io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if s.store.(*fakeStore).m[keyOf("keysec", "git.example.com")] != "tok-2" {
		t.Errorf("token not stored via 'store' alias")
	}
}

func TestGetReturnsStoredToken(t *testing.T) {
	fs := &fakeStore{m: map[string]string{keyOf("keysec", "git.example.com"): "tok-3"}}
	s := newShim(fs)
	var out bytes.Buffer
	err := s.Run(context.Background(), "get",
		strings.NewReader(credInput("https", "example.com", "", "u", "")),
		&out, io.Discard)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, err := Read(&out)
	if err != nil {
		t.Fatalf("re-read helper output: %v", err)
	}
	if got.Password != "tok-3" || got.Host != "example.com" {
		t.Errorf("get output = %+v", got)
	}
}

func TestGetSilentWhenNothingStored(t *testing.T) {
	s := newShim(&fakeStore{m: map[string]string{}})
	var out bytes.Buffer
	if err := s.Run(context.Background(), "get",
		strings.NewReader(credInput("https", "example.com", "", "u", "")),
		&out, io.Discard); err != nil {
		t.Fatalf("get with no stored cred must not error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected silence, got %q", out.String())
	}
}

func TestGetFailsLoudWhenLocked(t *testing.T) {
	fs := &fakeStore{m: map[string]string{}, getErr: keychain.ErrLocked}
	s := newShim(fs)
	var out bytes.Buffer
	err := s.Run(context.Background(), "get",
		strings.NewReader(credInput("https", "example.com", "", "u", "")),
		&out, io.Discard)
	if !errors.Is(err, keychain.ErrLocked) {
		t.Errorf("get err = %v, want ErrLocked (fail loudly, do not guess)", err)
	}
}

func TestRejectDeletes(t *testing.T) {
	fs := &fakeStore{m: map[string]string{keyOf("keysec", "git.example.com"): "stale"}}
	s := newShim(fs)
	err := s.Run(context.Background(), "reject",
		strings.NewReader(credInput("https", "example.com", "", "u", "stale")),
		io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, ok := fs.m[keyOf("keysec", "git.example.com")]; ok {
		t.Error("token still in store after reject")
	}
}

func TestRejectUnknownItemIsFine(t *testing.T) {
	fs := &fakeStore{m: map[string]string{}}
	s := newShim(fs)
	if err := s.Run(context.Background(), "reject",
		strings.NewReader(credInput("https", "example.com", "", "u", "x")),
		io.Discard, io.Discard); err != nil {
		t.Errorf("reject of unknown item should be a no-op, got %v", err)
	}
}

func TestUnknownAction(t *testing.T) {
	s := newShim(&fakeStore{m: map[string]string{}})
	if err := s.Run(context.Background(), "explode", strings.NewReader(""), io.Discard, io.Discard); err == nil {
		t.Error("unknown action should error")
	}
}
