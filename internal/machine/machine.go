// Package machine defines keysec's machine-readable data shapes: typed
// errors and structured outputs, for use by agents and scripts.
package machine

// Kind classifies an error so a caller can branch on it.
type Kind string

const (
	KindNotFound   Kind = "not_found"
	KindLocked     Kind = "locked"
	KindUsage      Kind = "usage"
	KindInvalidKey Kind = "invalid_key"
	KindIO         Kind = "io"
	KindInternal   Kind = "internal"
)

// Error is a typed application error. It renders as a flat JSON object
// so an agent can switch on the "error" field.
type Error struct {
	Kind    Kind   `json:"error"`
	Key     string `json:"key,omitempty"`
	Hint    string `json:"hint,omitempty"`
	Message string `json:"message,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string { return e.Message }

// ExitCode maps the kind to a process exit code: usage problems are 2,
// everything else is 1.
func (e *Error) ExitCode() int {
	if e.Kind == KindUsage || e.Kind == KindInvalidKey {
		return 2
	}
	return 1
}

// FromError returns err as an *Error, wrapping anything else as an
// internal error. A nil error yields nil.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}
	if e, ok := err.(*Error); ok {
		return e
	}
	return &Error{Kind: KindInternal, Message: err.Error()}
}

// NotFound reports a key that does not exist.
func NotFound(keyName, hint, message string) *Error {
	return &Error{Kind: KindNotFound, Key: keyName, Hint: hint, Message: message}
}

// Locked reports an inaccessible (locked) keychain.
func Locked(hint, message string) *Error {
	return &Error{Kind: KindLocked, Hint: hint, Message: message}
}

// Usage reports a bad invocation (wrong flags or arguments).
func Usage(message, hint string) *Error {
	return &Error{Kind: KindUsage, Hint: hint, Message: message}
}

// InvalidKey reports a key name that fails validation.
func InvalidKey(keyName, message string) *Error {
	return &Error{Kind: KindInvalidKey, Key: keyName, Hint: "names look like 'mytoken' or 'gitlab.repo_flay'", Message: message}
}

// IO reports an I/O or keychain failure that is not one of the above.
func IO(message string) *Error {
	return &Error{Kind: KindIO, Message: message}
}

// Value is the machine form of "get".
type Value struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// KeyInfo is one row of the machine form of "list".
type KeyInfo struct {
	Name  string `json:"name"`
	Saved string `json:"saved"`
	State string `json:"state"`
}

// List is the machine form of "list".
type List struct {
	Count int       `json:"count"`
	Keys  []KeyInfo `json:"keys"`
}

// Ack is a terse success signal for mutating commands (set/update/rm).
type Ack struct {
	OK     bool   `json:"ok"`
	Action string `json:"action"`
	Key    string `json:"key"`
}
