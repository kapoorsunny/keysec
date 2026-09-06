package machine

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestFromError(t *testing.T) {
	if FromError(nil) != nil {
		t.Error("FromError(nil) should be nil")
	}
	e := &Error{Kind: KindNotFound, Key: "k"}
	if got := FromError(e); got != e {
		t.Errorf("FromError(*Error) should return the same pointer")
	}
	got := FromError(errors.New("boom"))
	if got.Kind != KindInternal || got.Message != "boom" {
		t.Errorf("FromError(unknown) = %+v, want internal/boom", got)
	}
}

func TestExitCode(t *testing.T) {
	cases := map[Kind]int{
		KindUsage:      2,
		KindInvalidKey: 2,
		KindNotFound:   1,
		KindLocked:     1,
		KindIO:         1,
		KindInternal:   1,
	}
	for kind, want := range cases {
		if got := (&Error{Kind: kind}).ExitCode(); got != want {
			t.Errorf("%s.ExitCode() = %d, want %d", kind, got, want)
		}
	}
}

func TestErrorJSONShape(t *testing.T) {
	e := &Error{Kind: KindNotFound, Key: "gitlab.tken", Hint: "did you mean 'gitlab.api_token'?", Message: "no key called 'gitlab.tken'"}
	var m map[string]any
	if err := json.Unmarshal([]byte(marshal(t, e)), &m); err != nil {
		t.Fatal(err)
	}
	if m["error"] != "not_found" || m["key"] != "gitlab.tken" {
		t.Errorf("unexpected error object: %v", m)
	}
	if _, present := m["hint"]; !present {
		t.Errorf("hint should be present: %v", m)
	}
	e2 := &Error{Kind: KindUsage, Message: "usage"}
	var m2 map[string]any
	_ = json.Unmarshal([]byte(marshal(t, e2)), &m2)
	if _, ok := m2["key"]; ok {
		t.Errorf("key must be omitted when empty, got %v", m2)
	}
}

func TestDataShapes(t *testing.T) {
	var v map[string]any
	_ = json.Unmarshal([]byte(marshal(t, Value{Name: "k", Value: "secret"})), &v)
	if v["name"] != "k" || v["value"] != "secret" {
		t.Errorf("Value JSON = %v", v)
	}
	var l map[string]any
	_ = json.Unmarshal([]byte(marshal(t, List{Count: 1, Keys: []KeyInfo{{Name: "a.b", Saved: "2026-01-01", Rotates: "generate"}}})), &l)
	if l["count"].(float64) != 1 {
		t.Errorf("List JSON = %v", l)
	}
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %T: %v", v, err)
	}
	return string(b)
}
