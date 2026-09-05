package gitcred

import (
	"bytes"
	"testing"
)

func TestPercentRoundTrip(t *testing.T) {
	cases := []string{
		"plain",
		"with space",
		"token=123&x=y",
		"https://repo.flay.ai/path",
		"café",
		"pct%41",
		"tab\there",
	}
	for _, s := range cases {
		got, err := percentDecode(percentEncode(s))
		if err != nil {
			t.Errorf("round trip %q: %v", s, err)
			continue
		}
		if got != s {
			t.Errorf("round trip %q = %q", s, got)
		}
	}
}

func TestPercentEncodeForm(t *testing.T) {
	// git uses uppercase hex and leaves letters/digits bare.
	if got := percentEncode("a b"); got != "a%20b" {
		t.Errorf("percentEncode = %q, want a%%20b", got)
	}
	if got := percentEncode("A"); got != "A" {
		t.Errorf("percentEncode = %q, want A", got)
	}
}

func TestReadWriteRoundTrip(t *testing.T) {
	cred := Credential{
		Protocol: "https",
		Host:     "repo.flay.ai",
		Path:     "/flay/site.git",
		Username: "oauth2",
		Password: "glpat-abc 123=x",
	}
	var buf bytes.Buffer
	if err := cred.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	want := "protocol=https\n" +
		"host=repo.flay.ai\n" +
		"path=%2Fflay%2Fsite.git\n" +
		"username=oauth2\n" +
		"password=glpat-abc%20123%3Dx\n"
	if buf.String() != want {
		t.Errorf("Write output:\n%s\nwant:\n%s", buf.String(), want)
	}
	got, err := Read(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got != cred {
		t.Errorf("Read = %+v, want %+v", got, cred)
	}
}

func TestWriteOmitsEmptyPassword(t *testing.T) {
	cred := Credential{Protocol: "https", Host: "example.com"}
	var buf bytes.Buffer
	if err := cred.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if want := "protocol=https\nhost=example.com\n"; buf.String() != want {
		t.Errorf("Write = %q, want %q", buf.String(), want)
	}
}

func TestKeyFor(t *testing.T) {
	cases := []struct {
		cred    Credential
		want    string
		wantErr bool
	}{
		{
			cred: Credential{Protocol: "https", Host: "repo.flay.ai"},
			want: "git.repo.flay.ai",
		},
		{
			cred: Credential{Protocol: "https", Host: "repo.flay.ai", Path: "/flay/site.git"},
			want: "git.repo.flay.ai.flay.site",
		},
		{
			cred: Credential{Protocol: "https", Host: "github.com", Path: "/flay/site"},
			want: "git.github.com.flay.site",
		},
		{
			cred:    Credential{Protocol: "https"},
			wantErr: true,
		},
	}
	for _, c := range cases {
		got, err := KeyFor(c.cred)
		if c.wantErr {
			if err == nil {
				t.Errorf("KeyFor(%+v) = %q, want error", c.cred, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("KeyFor(%+v): %v", c.cred, err)
			continue
		}
		if got != c.want {
			t.Errorf("KeyFor(%+v) = %q, want %q", c.cred, got, c.want)
		}
	}
}
