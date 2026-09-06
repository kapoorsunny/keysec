package keychain

import (
	"context"
	"errors"
	"testing"
	"time"
)

// realisticDump-Mirroring the real shape of `security dump-keychain` on
// darwin 25.3.0: blocks open with keychain:, carry a class, an
// attributes section mixing hex tags and ASCII aliases, and timedate
// attributes.
const fixtureDump = `keychain: "/Users/me/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000000 <blob>=<NULL>
    0x00000007 <blob>="git"
    0x00000008 <blob>="gitlab.example.com.root.keysec"
    0x00000019 <timedate>=0x4143D7E8  "20250202105231Z\000"
    0x0000001A <timedate>=0x4143D7E8  "20260905105231Z\000"
    "cdat"<timedate>=0x4143D7E8  "20250202105231Z\000"
    "mdat"<timedate>=0x4143D7E8  "20260905105231Z\000"
    "svce"<blob>="git"
    "acct"<blob>="gitlab.example.com.root.keysec"
keychain: "/Users/me/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "svce"<blob>="keysec"
    "acct"<blob>="gitlab.api_token"
    "cdat"<timedate>=0x4143D7E8  "20260101120000Z\000"
    "mdat"<timedate>=0x4143D7E8  "20260101120000Z\000"
keychain: "/Users/me/Library/Keychains/login.keychain-db"
version: 512
class: "inet"
attributes:
    "srvr"<blob>="gitlab.example.com"
    "acct"<blob>="root"
keychain: "/Users/me/Library/Keychains/login.keychain-db"
version: 512
class: "cert"
attributes:
    "labl"<blob>="cacert"
`

func TestParseDump(t *testing.T) {
	entries, err := ParseDump([]byte(fixtureDump))
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d, want 2 (inet and cert blocks are skipped)", len(entries))
	}
	first := entries[0]
	if first.Service != "git" || first.Account != "gitlab.example.com.root.keysec" {
		t.Errorf("first = %q/%q, want git/gitlab.example.com.root.keysec", first.Service, first.Account)
	}
	if first.Created.Format("2006-01-02") != "2025-02-02" {
		t.Errorf("Created = %s, want 2025-02-02", first.Created)
	}
	if first.Modified.Format("2006-01-02") != "2026-09-05" {
		t.Errorf("Modified = %s, want 2026-09-05", first.Modified)
	}
	second := entries[1]
	if second.Service != "keysec" || second.Account != "gitlab.api_token" {
		t.Errorf("second = %q/%q, want keysec/gitlab.api_token", second.Service, second.Account)
	}
	if second.Modified.Format("2006-01-02") != "2026-01-01" {
		t.Errorf("second Modified = %s, want 2026-01-01", second.Modified)
	}
}

func TestParseDumpIteratesBlocks(t *testing.T) {
	if _, err := ParseDump([]byte(fixtureDump)); err != nil {
		t.Fatal(err)
	}
}

func TestParseDumpFallsBackModifiedToCreated(t *testing.T) {
	dump := `keychain: "..."
class: "genp"
attributes:
    "svce"<blob>="keysec"
    "acct"<blob>="only-created"
    "cdat"<timedate>=0x4143D7E8  "20260101120000Z\000"
`
	entries, err := ParseDump([]byte(dump))
	if err != nil {
		t.Fatalf("ParseDump: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(entries))
	}
	if !entries[0].Modified.Equal(entries[0].Created) {
		t.Errorf("Modified = %s, want to fall back to Created %s", entries[0].Modified, entries[0].Created)
	}
}

// The fail-loud contract: a dump that produced item blocks but zero
// structurally parseable blocks must error, never report an empty list.
func TestParseDumpSentinel(t *testing.T) {
	dump := `keychain: "/Users/me/Library/Keychains/login.keychain-db"
now: something completely different
stuff: here
`
	if _, err := ParseDump([]byte(dump)); !errors.Is(err, ErrDumpFormat) {
		t.Fatalf("err = %v, want ErrDumpFormat", err)
	}
}

func TestParseDumpEmptyIsLegit(t *testing.T) {
	entries, err := ParseDump(nil)
	if err != nil {
		t.Fatalf("ParseDump(empty) = %v, want nil", err)
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want no entries", entries)
	}
}

func TestParseDumpQuotedValueEscapes(t *testing.T) {
	if got := unquoteAttr(`"a\tb\"c"`); got != "a\tb\"c" {
		t.Errorf("unquoteAttr = %q", got)
	}
}

func TestParseKeyDate(t *testing.T) {
	ts := parseKeyDate("20260905105231Z")
	want := time.Date(2026, 9, 5, 10, 52, 31, 0, time.UTC)
	if !ts.Equal(want) {
		t.Errorf("parseKeyDate = %s, want %s", ts, want)
	}
	if !parseKeyDate("not a date").IsZero() {
		t.Error("parseKeyDate accepted garbage")
	}
}

func TestSecurityList(t *testing.T) {
	fr := &fakeRunner{stdout: fixtureDump}
	s := NewWithRunner(fr)
	entries, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d, want 1 (only the keysec service block)", len(entries))
	}
	if entries[0].Account != "gitlab.api_token" {
		t.Errorf("Account = %q, want gitlab.api_token", entries[0].Account)
	}
	// The one real key on this machine (svce "git") must not appear:
	// its coordinates live outside the reserved keysec service.
}

func TestSecurityListLocked(t *testing.T) {
	fr := &fakeRunner{
		stderr: "security: The specified keychain is not found.\n",
		err:    errors.New("boom"),
	}
	s := NewWithRunner(fr)
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("List on a failing dump-keychain should error")
	}
}

func TestSecurityListSentinelPassesThrough(t *testing.T) {
	fr := &fakeRunner{stdout: "keychain: \"...\"\nother: stuff\n"}
	s := NewWithRunner(fr)
	if _, err := s.List(context.Background()); !errors.Is(err, ErrDumpFormat) {
		t.Fatalf("err = %v, want ErrDumpFormat", err)
	}
}
