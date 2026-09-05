package rotator

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNewUnknownKind(t *testing.T) {
	if _, err := New(&Spec{Kind: "nope"}); err == nil {
		t.Fatal("New(nope) succeeded")
	}
}

func TestValidate(t *testing.T) {
	cases := []struct {
		spec    *Spec
		wantErr bool
	}{
		{&Spec{Kind: KindHTTP, URL: "https://x"}, false},
		{&Spec{Kind: KindHTTP}, true}, // no url
		{&Spec{Kind: KindHTTP, URL: "x", Auth: "basic:"}, true},
		{&Spec{Kind: KindScript}, true},                   // no script/body
		{&Spec{Kind: KindScript, Body: "echo hi"}, false}, //
		{&Spec{Kind: KindGenerate, Length: 0}, true},      // length must be >= 1
		{&Spec{Kind: KindGenerate, Length: 16, Charset: "ab"}, false},
		{&Spec{Kind: KindGenerate, Length: 16, Charset: strings.Repeat("a", 300)}, true},
		{&Spec{Kind: KindGenerate, Length: 4, Charset: strings.Repeat("é", 256)}, false}, // bytes double the runes
		{&Spec{Kind: KindGenerate, Length: 4, Charset: strings.Repeat("é", 257)}, true},
		{&Spec{Kind: KindVendorGithub, AuthKey: "gitlab.repo_flay"}, false},
		{&Spec{Kind: KindVendorGithub, AuthKey: "bad/name"}, true},
		{&Spec{Kind: KindVendorGitlab, Meta: map[string]string{"url": "https://git.example"}}, false},
		{&Spec{Kind: KindHTTP, URL: "https://x", Timeout: "notaduration"}, true},
		{&Spec{Kind: KindHTTP, URL: "https://x", Grace: "24h"}, false},
	}
	for i, c := range cases {
		if err := c.spec.Validate(); (err != nil) != c.wantErr {
			t.Errorf("case %d Validate = %v, wantErr=%v", i, err, c.wantErr)
		}
	}
}

func TestGenerateDefaults(t *testing.T) {
	r, err := New(&Spec{Kind: KindGenerate})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Rotate(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Value) != 32 {
		t.Errorf("default length = %d, want 32", len(res.Value))
	}
	for _, c := range res.Value {
		if !('A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9') {
			t.Fatalf("value contains non-alphanumeric %q", c)
		}
	}
	if res.ExpiresAt != nil || res.OldValidUntil != nil {
		t.Error("generate must produce no expiry metadata")
	}
}

func TestGenerateCustom(t *testing.T) {
	r, _ := New(&Spec{Kind: KindGenerate, Length: 10, Charset: "AB"})
	res, err := r.Rotate(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Value) != 10 {
		t.Errorf("length = %d, want 10", len(res.Value))
	}
	for _, c := range res.Value {
		if c != 'A' && c != 'B' {
			t.Fatalf("value char %q outside charset", c)
		}
	}
}

func TestGenerateUnique(t *testing.T) {
	r, _ := New(&Spec{Kind: KindGenerate, Length: 64})
	a, _ := r.Rotate(context.Background(), Input{})
	b, _ := r.Rotate(context.Background(), Input{})
	if a.Value == b.Value {
		t.Error("two rotations produced identical values")
	}
}

func TestGenerateMultibyteCharset(t *testing.T) {
	r, err := New(&Spec{Kind: KindGenerate, Length: 8, Charset: "é"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := r.Rotate(context.Background(), Input{})
	if err != nil {
		t.Fatal(err)
	}
	if n := utf8.RuneCountInString(res.Value); n != 8 {
		t.Fatalf("rune count = %d, want 8 (value %q)", n, res.Value)
	}
	for _, c := range res.Value {
		if c != 'é' {
			t.Fatalf("value contains %q, want only the charset rune", c)
		}
	}
}

func TestRenderTemplate(t *testing.T) {
	in := Input{Key: "k", Value: "v", Meta: map[string]string{"host": "example.com"}}
	got := RenderTemplate("/go/{key}/{value}?h={meta.host}&x={meta.missing}", in)
	want := "/go/k/v?h=example.com&x={meta.missing}"
	if got != want {
		t.Errorf("RenderTemplate = %q, want %q", got, want)
	}
}

func TestEnvMetaName(t *testing.T) {
	if got := EnvMetaName("root.password"); got != "ROOT_PASSWORD" {
		t.Errorf("EnvMetaName = %q", got)
	}
	if got := EnvMetaName("a-b_c"); got != "A_B_C" {
		t.Errorf("EnvMetaName = %q", got)
	}
}

func TestLookupNestedAndArrays(t *testing.T) {
	doc := map[string]any{
		"data": map[string]any{"token": "abc", "nested": []any{map[string]any{"x": 7}}},
	}
	if v, ok := Lookup(doc, "data.token"); !ok || v != "abc" {
		t.Errorf("data.token = %v, %v", v, ok)
	}
	if v, ok := Lookup(doc, "data.nested.0.x"); !ok || v != 7 {
		t.Errorf("data.nested.0.x = %v, %v", v, ok)
	}
	if _, ok := Lookup(doc, "data.missing"); ok {
		t.Error("missing path reported ok")
	}
}

func TestParseExpiry(t *testing.T) {
	if e, err := ParseExpiry("2030-01-01T00:00:00Z"); err != nil || e == nil {
		t.Errorf("ParseExpiry(iso) = %v, %v", e, err)
	}
	if e, err := ParseExpiry("1893456000"); err != nil || e == nil {
		t.Errorf("ParseExpiry(epoch) = %v, %v", e, err)
	}
	if e, err := ParseExpiry(""); err != nil || e != nil {
		t.Errorf("ParseExpiry(empty) = %v, %v", e, err)
	}
	if _, err := ParseExpiry("garbage"); err == nil {
		t.Error("ParseExpiry(garbage) succeeded")
	}
}

// Partially numeric strings must be rejected: a leading number alone must
// never stand in for the whole expiry.
func TestParseExpiryRejectsPartialNumbers(t *testing.T) {
	for _, s := range []string{"2030-01-01 12:00", "1893456000abc", " 1893456000"} {
		if _, err := ParseExpiry(s); err == nil {
			t.Errorf("ParseExpiry(%q) succeeded, want an error", s)
		}
	}
}
