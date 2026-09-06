// Package gitcred implements git's credential-helper protocol on top
// of the keysec store, so git can read and write tokens straight to
// the Keychain without a plaintext git-credentials file.
package gitcred

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// Credential is the small set of fields git's protocol carries.
type Credential struct {
	Protocol string
	Host     string
	Path     string
	Username string
	Password string
}

// Read parses a credential block from r: one percent-encoded
// key=value pair per line, as git feeds helpers on stdin.
func Read(r io.Reader) (Credential, error) {
	var c Credential
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSuffix(scanner.Text(), "\r")
		line = strings.TrimSuffix(line, "\n")
		if line == "" {
			continue
		}
		k, v, found := strings.Cut(line, "=")
		if !found {
			continue
		}
		v, err := percentDecode(v)
		if err != nil {
			return c, fmt.Errorf("cannot read credential: bad %s value", k)
		}
		switch k {
		case "protocol":
			c.Protocol = v
		case "host":
			c.Host = v
		case "path":
			c.Path = v
		case "username":
			c.Username = v
		case "password":
			c.Password = v
		}
	}
	if err := scanner.Err(); err != nil {
		return c, fmt.Errorf("cannot read credential: %v", err)
	}
	return c, nil
}

// Write writes the credential back in git's format. Empty fields are
// omitted; writing nothing at all is how a helper answers "I have no
// credentials for this host".
func (c Credential) Write(w io.Writer) error {
	fields := [][2]string{
		{"protocol", c.Protocol},
		{"host", c.Host},
		{"path", c.Path},
		{"username", c.Username},
		{"password", c.Password},
	}
	for _, f := range fields {
		if f[1] == "" {
			continue
		}
		if _, err := fmt.Fprintf(w, "%s=%s\n", f[0], percentEncode(f[1])); err != nil {
			return fmt.Errorf("cannot write credential: %v", err)
		}
	}
	return nil
}

// percentEncode encodes the way git does: letters, digits and the
// unreserved characters -._~ stay bare; every other byte becomes %XX
// with uppercase hex.
func percentEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isBare(c) {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

func isBare(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~'
}

// percentDecode reverses percentEncode.
func percentDecode(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		if i+2 >= len(s) {
			return "", fmt.Errorf("truncated percent escape in %q", s)
		}
		hi, err := hexDigit(s[i+1])
		if err != nil {
			return "", err
		}
		lo, err := hexDigit(s[i+2])
		if err != nil {
			return "", err
		}
		b.WriteByte(hi<<4 | lo)
		i += 2
	}
	return b.String(), nil
}

func hexDigit(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("bad percent escape %q", string(c))
}

// KeyFor derives the keysec key for a credential: "git." plus the
// host, plus one dot-joined segment per path piece (a trailing ".git"
// is dropped). It must be deterministic: git will ask again later with
// the same host/path and expect the same secret back.
func KeyFor(c Credential) (string, error) {
	if c.Host == "" {
		return "", fmt.Errorf("credential has no host")
	}
	name := "git." + sanitizeKeyPart(c.Host)
	for _, seg := range strings.Split(c.Path, "/") {
		seg = strings.TrimSpace(seg)
		if seg == "" {
			continue
		}
		seg = strings.TrimSuffix(seg, ".git")
		if seg == "" {
			continue
		}
		name += "." + sanitizeKeyPart(seg)
	}
	return name, nil
}

// sanitizeKeyPart maps a host or path segment onto keysec's key
// alphabet (letters, digits, dots, dashes) by replacing anything else
// with a dot and collapsing repeats.
func sanitizeKeyPart(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('.')
		}
	}
	s = b.String()
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", ".")
	}
	return strings.Trim(s, ".")
}
