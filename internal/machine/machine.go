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
	KindRotation   Kind = "rotation"
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
	return &Error{Kind: KindInvalidKey, Key: keyName, Hint: "names look like 'mytoken' or 'gitlab.api_token'", Message: message}
}

// IO reports an I/O or keychain failure that is not one of the above.
func IO(message string) *Error {
	return &Error{Kind: KindIO, Message: message}
}

// Rotation reports a failed secret rotation. The keychain is left
// unchanged: a rotator writes only after the provider succeeds.
func Rotation(keyName, message string) *Error {
	return &Error{Kind: KindRotation, Key: keyName, Message: message}
}

// RotationConfig reports a malformed rotator spec, distinct from a
// provider failure.
func RotationConfig(keyName, message string) *Error {
	return &Error{Kind: KindRotation, Key: keyName, Hint: "fix the spec with 'keysec rotator set " + keyName + " ...'", Message: message}
}

// Value is the machine form of "get".
type Value struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// KeyInfo is one row of the machine form of "list".
type KeyInfo struct {
	Name    string `json:"name"`
	Saved   string `json:"saved"`
	Rotates string `json:"rotates"` // rotator kind, or "" when no rotator
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

// RotateAck is the machine form of "rotate <key>". Dates are omitted
// (null) when a rotator produced no expiry information.
type RotateAck struct {
	OK            bool    `json:"ok"`
	Action        string  `json:"action"`
	Key           string  `json:"key"`
	RotatedAt     *string `json:"rotated_at,omitempty"`
	ExpiresAt     *string `json:"expires_at,omitempty"`
	OldValidUntil *string `json:"old_valid_until,omitempty"`
}

// RotatedOne is one succeeded rotation inside rotate --all.
type RotatedOne struct {
	Key       string  `json:"key"`
	RotatedAt *string `json:"rotated_at,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

// RotationFailure is one failed rotation inside rotate --all, expressed
// as a machine error so callers can branch on the kind.
type RotationFailure struct {
	*Error
}

// RotateBulk is the machine form of "rotate --all".
type RotateBulk struct {
	OK      bool              `json:"ok"`
	Action  string            `json:"action"`
	Rotated []RotatedOne      `json:"rotated"`
	Failed  []RotationFailure `json:"failed"`
}

// RotatorAck is the machine form of "rotator set/rm".
type RotatorAck struct {
	OK     bool   `json:"ok"`
	Action string `json:"action"` // "rotator.set" | "rotator.removed" | ...
	Key    string `json:"key"`
}

// AuditStatus is the lifecycle status of one audited key.
type AuditStatus string

const (
	AuditOK          AuditStatus = "OK"
	AuditExpiresSoon AuditStatus = "EXPIRES_SOON"
	AuditExpired     AuditStatus = "EXPIRED"
	AuditNever       AuditStatus = "NEVER_EXPIRES"
	AuditNoRotator   AuditStatus = "NO_ROTATOR"
)

// AuditKey is one row of the machine form of "audit".
type AuditKey struct {
	Name      string      `json:"name"`
	Saved     string      `json:"saved"`
	Rotates   string      `json:"rotates"`
	Status    AuditStatus `json:"status"`
	ExpiresAt *string     `json:"expires_at,omitempty"`
}

// Audit is the machine form of "audit".
type Audit struct {
	Count int        `json:"count"`
	Keys  []AuditKey `json:"keys"`
}

// RunEntry is one handoff recorded by "keysec run": which secret keys
// were injected into which command, and when. Sha is the entry's link
// in the tamper-evident chain.
type RunEntry struct {
	Seq int      `json:"seq"`
	At  string   `json:"at"`
	Cmd string   `json:"command"`
	Env []string `json:"secret_keys"`
	Sha string   `json:"sha,omitempty"`
}

// Runs is the machine form of "keysec runs". Tampered marks a log whose
// stored chain failed verification.
type Runs struct {
	Count    int        `json:"count"`
	Entries  []RunEntry `json:"entries"`
	Tampered bool       `json:"tampered,omitempty"`
}

// RunsReset is the machine form of "keysec runs --yes".
type RunsReset struct {
	OK      bool   `json:"ok"`
	Action  string `json:"action"`  // "runs.reset"
	Cleared int    `json:"cleared"` // entries removed (best-effort on a corrupt log)
}
