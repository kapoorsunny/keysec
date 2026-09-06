package key

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in       string
		wantSvc  string
		wantAcct string
		wantErr  bool
	}{
		{"mytoken", "keysec", "mytoken", false},
		{"gitlab.api_token", "keysec", "gitlab.api_token", false},
		{"git.gitlab.example.com", "keysec", "git.gitlab.example.com", false},
		{"a.b.c.d", "keysec", "a.b.c.d", false},
		{"A1-b_c", "keysec", "A1-b_c", false},
		{"", "", "", true},
		{".lead", "", "", true},
		{"trail.", "", "", true},
		{"bad/path", "", "", true},
		{"spa ce", "", "", true},
		{"foo.rotator", "", "", true}, // reserved companion suffix
	}
	for _, c := range cases {
		k, err := Parse(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("Parse(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr {
			continue
		}
		if k.Service != c.wantSvc || k.Account != c.wantAcct {
			t.Errorf("Parse(%q) = %q/%q, want %q/%q", c.in, k.Service, k.Account, c.wantSvc, c.wantAcct)
		}
	}
}

// ReservedSuffix means a name is a companion spec entry, never a key, no
// matter how the name is split up.
func TestParseRejectsReservedSuffix(t *testing.T) {
	for _, in := range []string{"foo.rotator", "a.b.rotator", ".rotator"} {
		k, err := Parse(in)
		if err == nil {
			t.Errorf("Parse(%q) succeeded, want reserved-suffix error", in)
		}
		if k.Service != "" || k.Account != "" {
			t.Errorf("Parse(%q) returned %q/%q on error, want empty", in, k.Service, k.Account)
		}
	}
	if _, err := Parse("rotator"); err != nil {
		t.Errorf("Parse(rotator) failed: %v (bare 'rotator' is a valid name)", err)
	}
}

// ParseServiceAccount maps enumerated Keychain coordinates back to a key,
// and refuses anything outside the reserved service.
func TestParseServiceAccount(t *testing.T) {
	if k, err := ParseServiceAccount("keysec", "gitlab.api_token"); err != nil || k.Name != "gitlab.api_token" {
		t.Errorf("ParseServiceAccount(keysec, gitlab.api_token) = %+v, %v", k, err)
	}
	if _, err := ParseServiceAccount("git", "gitlab.example.com"); err == nil {
		t.Error("ParseServiceAccount(git, ...) succeeded, want error")
	}
	if _, err := ParseServiceAccount("keysec", "foo.rotator"); err == nil {
		t.Error("ParseServiceAccount with .rotator account succeeded, want error")
	}
}

// Double dots, leading and trailing dots all create empty segments and
// must be rejected.
func TestParseEmptySegments(t *testing.T) {
	for _, in := range []string{"a..b", "a.b.", "a..", ".a.b"} {
		if _, err := Parse(in); err == nil {
			t.Errorf("Parse(%q) succeeded, want an empty-segment error", in)
		}
	}
}

// IsCompanion reports whether an enumerated account is a rotator
// companion entry.
func TestIsCompanion(t *testing.T) {
	if !IsCompanion("foo.rotator") {
		t.Error("IsCompanion(foo.rotator) = false")
	}
	if IsCompanion("rotator") {
		t.Error("IsCompanion(rotator) = true, want false (must end with .rotator)")
	}
	if IsCompanion("foo") || IsCompanion("foo.rotatorx") {
		t.Error("IsCompanion wrongly matched")
	}
}

// CompanionName swaps a key name back and forth with its companion
// account.
func TestCompanionName(t *testing.T) {
	if got := CompanionName("foo"); got != "foo.rotator" {
		t.Errorf("CompanionName(foo) = %q", got)
	}
	if got, ok := ParentName("foo.rotator"); !ok || got != "foo" {
		t.Errorf("ParentName(foo.rotator) = %q, %v", got, ok)
	}
	if _, ok := ParentName("foo"); ok {
		t.Error("ParentName(foo) = ok, want false")
	}
}

func TestSuggest(t *testing.T) {
	cands := []string{"gitlab.api_token", "github.token", "db.password"}
	if got := Suggest("gitlab.api_token", cands); got != "gitlab.api_token" {
		t.Errorf("Suggest = %q, want gitlab.api_token", got)
	}
	if got := Suggest("db.pssword", cands); got != "db.password" {
		t.Errorf("Suggest = %q, want db.password", got)
	}
	if got := Suggest("zzzzzz", cands); got != "" {
		t.Errorf("Suggest = %q, want empty (no close match)", got)
	}
}
