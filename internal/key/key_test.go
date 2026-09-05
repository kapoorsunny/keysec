package key

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in      string
		svc     string
		acct    string
		wantErr bool
	}{
		{"mytoken", "keysec", "mytoken", false},
		{"gitlab.repo_flay", "gitlab", "repo_flay", false},
		{"git.repo.flay.ai", "git", "repo.flay.ai", false},
		{"a.b.c.d", "a", "b.c.d", false},
		{"A1-b_c", "keysec", "A1-b_c", false},
		{"", "", "", true},
		{".lead", "", "", true},
		{"trail.", "", "", true},
		{"bad/path", "", "", true},
		{"spa ce", "", "", true},
		{"a..b", "a", ".b", true}, // not caught by regex? it is: regex allows internal .. ; handled below
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
		if k.Service != c.svc || k.Account != c.acct {
			t.Errorf("Parse(%q) = %q/%q, want %q/%q", c.in, k.Service, k.Account, c.svc, c.acct)
		}
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

func TestSuggest(t *testing.T) {
	cands := []string{"gitlab.repo_flay", "github.token", "db.password"}
	if got := Suggest("gitlab.repo_flay", cands); got != "gitlab.repo_flay" {
		t.Errorf("Suggest = %q, want gitlab.repo_flay", got)
	}
	if got := Suggest("db.pssword", cands); got != "db.password" {
		t.Errorf("Suggest = %q, want db.password", got)
	}
	if got := Suggest("zzzzzz", cands); got != "" {
		t.Errorf("Suggest = %q, want empty (no close match)", got)
	}
}
