package keychain

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ParseDump parses the output of `security dump-keychain` into the
// metadata of every item it describes (values are withheld from the
// dump by modern macOS, so none ever appear here).
//
// The output is a sequence of item blocks. Each block opens with a
// keychain: line, a version, a quoted class, and an attributes section
// whose lines carry a hex tag and/or a human-aliased attribute of the
// form "name"<type>=value. Dates are ASCII aliases of the form
// "cdat"/"mdat" with a quoted "YYYYMMDDHHMMSSZ" timestamp.
//
// ParseDump never fabricates an empty list: if item blocks exist but not
// one of them parsed as a structurally valid block, it returns
// ErrDumpFormat so the caller fails loudly instead of hiding keys.
func ParseDump(data []byte) ([]Entry, error) {
	var entries []Entry
	var cur []string
	blocks, structured := 0, 0
	flush := func() {
		if !hasContent(cur) {
			cur = nil
			return
		}
		blocks++
		e, ok := parseBlock(cur)
		if ok {
			structured++
		}
		if e.Service != "" && e.Account != "" {
			entries = append(entries, e)
		}
		cur = nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "keychain:") {
			flush()
		}
		cur = append(cur, line)
	}
	flush()
	if blocks > 0 && structured == 0 {
		return nil, ErrDumpFormat
	}
	return entries, nil
}

// hasContent reports whether a collected block contains a non-blank,
// non-comment line, so blank input is treated as "nothing in the
// keychain", not as an unparseable dump.
func hasContent(lines []string) bool {
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			return true
		}
	}
	return false
}

var classRe = regexp.MustCompile(`^\s*class:\s*"([^"]*)"`)
var attrAliasRe = regexp.MustCompile(`^\s*"([a-zA-Z0-9_]+)"<[a-zA-Z0-9_]+>=([^\r\n]*)$`)

// parseBlock interprets one item block. ok is true when the block was
// structurally recognised (it has a class line); only class "genp"
// items carry a service and account, and only those become an Entry.
func parseBlock(lines []string) (Entry, bool) {
	var e Entry
	var keyClass string
	hasClass := false
	for _, line := range lines {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if m := classRe.FindStringSubmatch(s); m != nil {
			keyClass = m[1]
			hasClass = true
			continue
		}
		m := attrAliasRe.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		name, val := m[1], m[2]
		switch name {
		case "svce":
			e.Service = unquoteAttr(val)
		case "acct":
			e.Account = unquoteAttr(val)
		case "cdat":
			if ts, ok := timeToken(val); ok {
				e.Created = parseKeyDate(ts)
			}
		case "mdat":
			if ts, ok := timeToken(val); ok {
				e.Modified = parseKeyDate(ts)
			}
		}
	}
	if !hasClass {
		return Entry{}, false
	}
	if keyClass != "genp" {
		return Entry{}, true // structurally fine, not a secret item
	}
	if e.Modified.IsZero() && !e.Created.IsZero() {
		e.Modified = e.Created
	}
	return e, true
}

// unquoteAttr decodes a quoted attribute value printed by security(1).
// It is happy with plain double quotes and Go-style escapes, falling
// back to stripping the quotes when either fails.
func unquoteAttr(v string) string {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return v
	}
	if s, err := strconv.Unquote(v); err == nil {
		return s
	}
	return v[1 : len(v)-1]
}

// timeToken extracts the quoted date token from a timedate attribute
// value such as: 0x4143D7E8  "20220502122423Z\000"
func timeToken(v string) (string, bool) {
	start := strings.IndexByte(v, '"')
	if start < 0 {
		return "", false
	}
	for i := start + 1; i < len(v); i++ {
		if v[i] == '"' {
			inner := v[start+1 : i]
			// security prints a trailing \000 (four literal chars).
			inner = strings.TrimSuffix(inner, `\000`)
			if len(inner) >= 14 && strings.HasSuffix(inner, "Z") {
				return inner, true
			}
			return "", false
		}
	}
	return "", false
}

// parseKeyDate parses security(1)'s "YYYYMMDDHHMMSSZ" timestamp.
func parseKeyDate(s string) time.Time {
	s = strings.TrimSuffix(s, "Z")
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}
