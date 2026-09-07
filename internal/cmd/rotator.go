package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kapoorsunny/keysec/internal/key"
	"github.com/kapoorsunny/keysec/internal/keychain"
	"github.com/kapoorsunny/keysec/internal/machine"
	"github.com/kapoorsunny/keysec/internal/rotator"
	"github.com/kapoorsunny/keysec/internal/ui"
)

// Rotator implements the "keysec rotator" group: get, set and rm a
// key's rotation spec. The spec lives secret-free in a <key>.rotator
// companion entry, so it can be inspected without reading the secret.
func (a *App) Rotator(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return machine.Usage("usage: keysec rotator <get|set|rm> <key>",
			"kinds: "+strings.Join(rotator.Kinds, ", "))
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "get":
		return a.rotatorGet(ctx, rest)
	case "set":
		return a.rotatorSet(ctx, rest)
	case "rm":
		return a.rotatorRemove(ctx, rest)
	default:
		return machine.Usage("unknown rotator subcommand '"+sub+"'", "usage: keysec rotator <get|set|rm> <key>")
	}
}

// rotatorGet prints a key's rotator spec: every non-secret field plus
// the lifecycle state. The secret's value is never read.
func (a *App) rotatorGet(ctx context.Context, args []string) error {
	if len(args) != 1 {
		return machine.Usage("usage: keysec rotator get <key>", "")
	}
	k, err := parseKey(args[0])
	if err != nil {
		return err
	}
	spec, ok, err := a.loadSpec(ctx, k.Name)
	if err != nil {
		return machine.RotationConfig(k.Name, err.Error())
	}
	if !ok {
		return machine.NotFound(k.Name,
			"set one: keysec rotator set "+k.Name+" --kind generate --length 48",
			"no rotator configured for '"+k.Name+"'")
	}
	if a.ui.InJSON() {
		return a.ui.JSON(struct {
			Name string        `json:"name"`
			Spec *rotator.Spec `json:"spec"`
		}{k.Name, spec})
	}
	a.ui.Outln("rotator for '%s'", k.Name)
	a.ui.Table([]string{"FIELD", "VALUE"}, specRows(spec))
	if spec.RotatedAt != "" {
		a.ui.Hint("last rotated at %s", spec.RotatedAt)
	}
	if spec.ExpiresAt != "" {
		a.ui.Hint("current value expires at %s", spec.ExpiresAt)
	}
	return nil
}

// specRows flattens a spec into FIELD/VALUE rows for the table renderer.
func specRows(s *rotator.Spec) [][]string {
	rows := [][]string{{"kind", s.Kind}}
	add := func(name, v string) {
		if v != "" {
			rows = append(rows, []string{name, v})
		}
	}
	if s.Length > 0 {
		add("length", strconv.Itoa(s.Length))
	}
	add("charset", s.Charset)
	add("url", s.URL)
	add("method", s.Method)
	add("auth", s.Auth)
	add("auth_key", s.AuthKey)
	add("value", s.Value)
	add("new_expires", s.NewExpires)
	add("grace", s.Grace)
	add("script", s.Script)
	// An inline body is often a whole script; show enough to confirm it is
	// set and which one it is, since otherwise it is invisible here.
	if s.Body != "" {
		first, _, more := strings.Cut(s.Body, "\n")
		if more {
			first += " …"
		}
		add("body", fmt.Sprintf("%s  (%d bytes)", first, len(s.Body)))
	}
	add("interpreter", s.Interpreter)
	add("timeout", s.Timeout)
	for _, mk := range sortedKeys(s.Meta) {
		add("meta."+mk, s.Meta[mk])
	}
	return rows
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// rotatorSet creates or updates a rotator spec. Flags merge onto the
// existing spec; --spec replaces its configuration wholesale (state is
// carried over). Switching kind clears the previous kind's fields.
func (a *App) rotatorSet(ctx context.Context, args []string) error {
	flags, positional, metas, err := parseRotatorFlags(args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return machine.Usage("usage: keysec rotator set <key> [flags]", "see: keysec help")
	}
	k, err := parseKey(positional[0])
	if err != nil {
		return err
	}
	cur, _, lerr := a.loadSpec(ctx, k.Name)
	if lerr != nil {
		return machine.RotationConfig(k.Name, lerr.Error())
	}
	prevKind := ""
	if cur == nil {
		cur = &rotator.Spec{Meta: map[string]string{}}
	} else {
		prevKind = cur.Kind
	}
	if cur.Meta == nil {
		cur.Meta = map[string]string{}
	}

	set := map[string]bool{}
	if raw, ok := flags["--spec"]; ok {
		var ns rotator.Spec
		if err := json.Unmarshal([]byte(raw), &ns); err != nil {
			return machine.Usage("the --spec JSON is not valid: "+err.Error(), "")
		}
		prevKind = cur.Kind
		carryState(cur, &ns)
		cur = &ns
		if cur.Meta == nil {
			cur.Meta = map[string]string{}
		}
		set["spec"] = true
	}
	if v, ok := flags["--kind"]; ok {
		if cur.Kind != v {
			prevKind = cur.Kind
		}
		cur.Kind = v
		set["kind"] = true
	}
	if v, ok := flags["--url"]; ok {
		cur.URL = v
		set["url"] = true
	}
	if v, ok := flags["--method"]; ok {
		cur.Method = v
		set["method"] = true
	}
	if v, ok := flags["--auth"]; ok {
		cur.Auth = v
		set["auth"] = true
	}
	if v, ok := flags["--auth-key"]; ok {
		cur.AuthKey = v
		set["auth_key"] = true
	}
	if v, ok := flags["--value"]; ok {
		cur.Value = v
		set["value"] = true
	}
	if v, ok := flags["--new-expires"]; ok {
		cur.NewExpires = v
		set["new_expires"] = true
	}
	if v, ok := flags["--grace"]; ok {
		cur.Grace = v
		set["grace"] = true
	}
	if v, ok := flags["--script"]; ok {
		cur.Script = v
		set["script"] = true
	}
	if v, ok := flags["--body"]; ok {
		cur.Body = v
		set["body"] = true
	}
	if v, ok := flags["--body-file"]; ok {
		var b []byte
		var err error
		if v == "-" {
			b, err = io.ReadAll(a.stdin)
		} else {
			b, err = os.ReadFile(v)
		}
		if err != nil {
			return machine.IO(err.Error())
		}
		cur.Body = string(b)
		set["body"] = true
	}
	if v, ok := flags["--interpreter"]; ok {
		cur.Interpreter = v
		set["interpreter"] = true
	}
	if v, ok := flags["--timeout"]; ok {
		cur.Timeout = v
		set["timeout"] = true
	}
	if v, ok := flags["--length"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil {
			return machine.Usage("--length expects a number, got '"+v+"'", "")
		}
		cur.Length = n
		set["length"] = true
	}
	if v, ok := flags["--charset"]; ok {
		cur.Charset = v
		set["charset"] = true
	}
	for _, kv := range metas {
		eq := strings.IndexByte(kv, '=')
		if eq <= 0 {
			return machine.Usage("--meta expects key=value, got '"+kv+"'", "")
		}
		cur.Meta[kv[:eq]] = kv[eq+1:]
		set["meta."+kv[:eq]] = true
	}

	if prevKind != "" && prevKind != cur.Kind && !set["spec"] {
		// Only flag-driven kind switches drop the previous kind's fields.
		// A --spec replace is the user's complete configuration, so its
		// fields must survive a kind change.
		clearKindFields(cur, set)
	}
	if err := cur.Validate(); err != nil {
		return machine.RotationConfig(k.Name, err.Error())
	}
	if len(cur.Meta) == 0 {
		cur.Meta = nil
	}
	cur.SpecUpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := a.saveSpec(ctx, k.Name, cur); err != nil {
		return a.storeError(err)
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.RotatorAck{OK: true, Action: "rotator.set", Key: k.Name})
	}
	a.ui.Success("saved the rotator for '%s' (kind: %s)", k.Name, cur.Kind)
	a.ui.Hint("rotate it whenever you like: keysec rotate %s", k.Name)
	return nil
}

// parseRotatorFlags splits rotator set args into flag values, positional
// key names and repeated --meta items. Every --flag takes a value, as
// "--flag=v" or "--flag v".
func parseRotatorFlags(args []string) (flags map[string]string, positional, metas []string, err error) {
	flags = map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			positional = append(positional, arg)
			continue
		}
		// "--flag=" carries an explicit empty value (the only way to clear
		// a field); "--flag" takes the next argument. Telling them apart
		// by whether the value is empty would swallow the following
		// argument and silently misparse the rest of the line.
		name, val := arg, ""
		inline := false
		if eq := strings.IndexByte(arg, '='); eq >= 0 {
			name, val, inline = arg[:eq], arg[eq+1:], true
		}
		if name == "--meta" {
			if !inline {
				i++
				if i >= len(args) {
					return nil, nil, nil, machine.Usage("--meta needs key=value", "")
				}
				val = args[i]
			}
			metas = append(metas, val)
			continue
		}
		if !inline {
			i++
			if i >= len(args) {
				return nil, nil, nil, machine.Usage("flag "+name+" needs a value", "")
			}
			val = args[i]
		}
		flags[name] = val
	}
	return flags, positional, metas, nil
}

// carryState copies lifecycle state from old onto ns so a wholesale
// --spec cannot wipe the rotation history.
func carryState(old, ns *rotator.Spec) {
	if ns.RotatedAt == "" {
		ns.RotatedAt = old.RotatedAt
	}
	if ns.ExpiresAt == "" {
		ns.ExpiresAt = old.ExpiresAt
	}
	if ns.OldValidUntil == "" {
		ns.OldValidUntil = old.OldValidUntil
	}
	if ns.LastCreatedID == "" {
		ns.LastCreatedID = old.LastCreatedID
	}
	if ns.SpecUpdatedAt == "" {
		ns.SpecUpdatedAt = old.SpecUpdatedAt
	}
}

// clearKindFields drops every kind-specific field the user did not set
// this invocation, so switching kinds cannot inherit a stale config.
func clearKindFields(s *rotator.Spec, set map[string]bool) {
	if !set["url"] {
		s.URL = ""
	}
	if !set["method"] {
		s.Method = ""
	}
	if !set["auth"] {
		s.Auth = ""
	}
	if !set["auth_key"] {
		s.AuthKey = ""
	}
	if !set["value"] {
		s.Value = ""
	}
	if !set["new_expires"] {
		s.NewExpires = ""
	}
	if !set["script"] {
		s.Script = ""
	}
	if !set["body"] {
		s.Body = ""
	}
	if !set["interpreter"] {
		s.Interpreter = ""
	}
	if !set["length"] {
		s.Length = 0
	}
	if !set["charset"] {
		s.Charset = ""
	}
}

// rotatorRemove deletes a key's rotator spec. The secret is untouched.
func (a *App) rotatorRemove(ctx context.Context, args []string) error {
	yes := false
	positional := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "--yes" {
			yes = true
			continue
		}
		positional = append(positional, arg)
	}
	if len(positional) != 1 {
		return machine.Usage("usage: keysec rotator rm <key> [--yes]", "--yes skips the confirmation")
	}
	k, err := parseKey(positional[0])
	if err != nil {
		return err
	}
	has, err := a.store.Has(ctx, key.ReservedService, key.CompanionName(k.Name))
	if err != nil {
		return a.storeError(err)
	}
	if !has {
		return machine.NotFound(k.Name,
			"set one: keysec rotator set "+k.Name+" --kind generate --length 48",
			"no rotator configured for '"+k.Name+"'")
	}
	ok, err := a.prompts.Confirm(fmt.Sprintf("remove the rotator for '%s'", k.Name), yes)
	if err != nil {
		if errors.Is(err, ui.ErrNotConfirmed) {
			return machine.Usage("removal was not confirmed", "pass --yes to remove without a prompt")
		}
		return machine.IO(err.Error())
	}
	if !ok {
		if a.ui.InJSON() {
			return a.ui.JSON(machine.RotatorAck{OK: false, Action: "rotator.kept", Key: k.Name})
		}
		a.ui.Note("ok, kept the rotator for '%s'", k.Name)
		return nil
	}
	if err := a.store.Delete(ctx, key.ReservedService, key.CompanionName(k.Name)); err != nil && !errors.Is(err, keychain.ErrNotFound) {
		return a.storeError(err)
	}
	if a.ui.InJSON() {
		return a.ui.JSON(machine.RotatorAck{OK: true, Action: "rotator.removed", Key: k.Name})
	}
	a.ui.Success("removed the rotator for '%s'", k.Name)
	a.ui.Hint("the secret itself is unchanged")
	return nil
}
