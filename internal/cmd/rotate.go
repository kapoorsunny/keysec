package cmd

import (
	"context"
	"errors"
	"fmt"
	"time"

	"repo.flay.ai/root/keysec/internal/key"
	"repo.flay.ai/root/keysec/internal/keychain"
	"repo.flay.ai/root/keysec/internal/machine"
	"repo.flay.ai/root/keysec/internal/rotator"
)

// Rotate implements "keysec rotate <key> [--plan]" and the sweep forms
// "keysec rotate --all [--due] [--plan]". Providers run first; nothing
// is written until one succeeds (see rotateCore).
func (a *App) Rotate(ctx context.Context, args []string) error {
	plan, all, due := false, false, false
	var rest []string
	for _, arg := range args {
		switch arg {
		case "--plan", "--dry-run", "--dry":
			plan = true
		case "--all":
			all = true
		case "--due":
			due = true
		default:
			rest = append(rest, arg)
		}
	}
	if all || due {
		return a.rotateBulk(ctx, rest, plan, all, due)
	}
	if len(rest) != 1 {
		return machine.Usage("usage: keysec rotate <key> [--plan]", "to rotate every due key: keysec rotate --all --due")
	}
	ack, err := a.rotateCore(ctx, rest[0], plan)
	if err != nil {
		return err
	}
	if a.ui.InJSON() {
		return a.ui.JSON(ack)
	}
	if plan {
		a.ui.Outln("plan for '%s'", ack.Key)
		if ack.ExpiresAt != nil {
			a.ui.Hint("current value expires at %s", *ack.ExpiresAt)
		}
	} else {
		a.ui.Success("rotated '%s'", ack.Key)
		if ack.ExpiresAt != nil {
			a.ui.Hint("new value expires at %s", *ack.ExpiresAt)
		}
	}
	return nil
}

// rotateCore does one rotation and returns its machine ack. It is
// shared by single rotations and sweeps so both behave identically.
func (a *App) rotateCore(ctx context.Context, name string, plan bool) (*machine.RotateAck, error) {
	k, err := parseKey(name)
	if err != nil {
		return nil, err
	}
	value, err := a.store.Get(ctx, k.Service, k.Account)
	if err != nil {
		if errors.Is(err, keychain.ErrNotFound) {
			return nil, a.notFoundError(ctx, k.Name)
		}
		return nil, a.storeError(err)
	}
	spec, ok, err := a.loadSpec(ctx, k.Name)
	if err != nil {
		return nil, machine.RotationConfig(k.Name, err.Error())
	}
	if !ok {
		return nil, machine.NotFound(k.Name,
			"add a rotator: keysec rotator set "+k.Name+" --kind generate --length 48",
			"no rotator configured for '"+k.Name+"'")
	}
	if err := spec.Validate(); err != nil {
		return nil, machine.RotationConfig(k.Name, err.Error())
	}
	credential := value
	if spec.AuthKey != "" {
		ak, perr := key.Parse(spec.AuthKey)
		if perr != nil {
			return nil, machine.RotationConfig(k.Name, "auth_key: "+perr.Error())
		}
		credential, err = a.store.Get(ctx, ak.Service, ak.Account)
		if err != nil {
			if errors.Is(err, keychain.ErrNotFound) {
				return nil, machine.Rotation(k.Name, "the auth_key '"+spec.AuthKey+"' has no stored value")
			}
			return nil, a.storeError(err)
		}
	}
	now := nowStamp()
	if plan {
		return &machine.RotateAck{OK: true, Action: "plan", Key: k.Name, ExpiresAt: strPtr(spec.ExpiresAt)}, nil
	}
	r, err := rotator.New(spec)
	if err != nil {
		return nil, machine.RotationConfig(k.Name, err.Error())
	}
	res, rerr := r.Rotate(ctx, rotator.Input{Key: k.Name, Value: value, Credential: credential, Meta: spec.Meta})
	if rerr != nil {
		return nil, machine.Rotation(k.Name, "rotation failed: "+rerr.Error())
	}
	if res.Value == "" {
		return nil, machine.Rotation(k.Name, "the rotator returned an empty value")
	}
	if err := a.store.Put(ctx, k.Service, k.Account, res.Value); err != nil {
		return nil, machine.Rotation(k.Name, "provider succeeded but storing the new value failed: "+err.Error())
	}
	if res.ExpiresAt != nil {
		spec.ExpiresAt = res.ExpiresAt.UTC().Format(time.RFC3339)
	}
	if res.OldValidUntil != nil {
		spec.OldValidUntil = res.OldValidUntil.UTC().Format(time.RFC3339)
	}
	spec.RotatedAt = now
	spec.SpecUpdatedAt = now
	if res.ID != "" {
		spec.LastCreatedID = res.ID
	}
	// The secret is already rotated; failing to update the spec must not
	// fail the command, but the user should hear about it.
	if err := a.saveSpec(ctx, k.Name, spec); err != nil {
		a.ui.Hint("rotated '%s', but updating its rotator spec failed: %v", k.Name, err)
	}
	if res.Warning != "" {
		a.ui.Hint("%s", res.Warning)
	}
	return &machine.RotateAck{
		OK:            true,
		Action:        "rotated",
		Key:           k.Name,
		RotatedAt:     strPtr(now),
		ExpiresAt:     strPtr(spec.ExpiresAt),
		OldValidUntil: strPtr(spec.OldValidUntil),
	}, nil
}

// rotateBulk implements "rotate --all [--due] [--plan]". Without --all
// only keys with a recorded expiry up to now are touched. A failing key
// does not stop the sweep; the bulk still exits non-zero.
func (a *App) rotateBulk(ctx context.Context, rest []string, plan, all, due bool) error {
	if len(rest) != 0 {
		return machine.Usage("usage: keysec rotate --all [--due] [--plan]", "")
	}
	keys, err := a.listedKeys(ctx)
	if err != nil {
		return err
	}
	bulk := &machine.RotateBulk{OK: true, Action: "rotated"}
	if plan {
		bulk.Action = "plan"
	}
	for _, k := range keys {
		if k.rotates == "" {
			continue // no rotator configured
		}
		if !all {
			spec, ok, err := a.loadSpec(ctx, k.name)
			if err != nil || !ok {
				bulk.Failed = append(bulk.Failed, machine.RotationFailure{
					Error: machine.FromError(machine.RotationConfig(k.name, "rotator spec unreadable")),
				})
				bulk.OK = false
				continue
			}
			exp, perr := rotator.ParseExpiry(spec.ExpiresAt)
			if perr != nil || exp == nil || exp.After(time.Now()) {
				continue // no expiry recorded or not due yet
			}
		}
		ack, err := a.rotateCore(ctx, k.name, plan)
		if err != nil {
			bulk.Failed = append(bulk.Failed, machine.RotationFailure{Error: machine.FromError(err)})
			bulk.OK = false
			continue
		}
		if plan {
			bulk.Rotated = append(bulk.Rotated, machine.RotatedOne{Key: k.name})
			continue
		}
		bulk.Rotated = append(bulk.Rotated, machine.RotatedOne{Key: k.name, RotatedAt: ack.RotatedAt, ExpiresAt: ack.ExpiresAt})
	}
	if a.ui.InJSON() {
		a.ui.JSON(bulk)
		if bulk.OK {
			return nil
		}
		return machine.Rotation("", fmt.Sprintf("%d of %d rotations failed", len(bulk.Failed), len(bulk.Failed)+len(bulk.Rotated)))
	}
	if plan {
		a.ui.Outln("would rotate %d key%s", len(bulk.Rotated), plural(len(bulk.Rotated)))
	} else {
		a.ui.Success("rotated %d key%s", len(bulk.Rotated), plural(len(bulk.Rotated)))
	}
	for _, f := range bulk.Failed {
		a.ui.Fail("%s: %s", f.Key, f.Message)
	}
	if bulk.OK {
		return nil
	}
	return machine.Rotation("", fmt.Sprintf("%d of %d rotations failed", len(bulk.Failed), len(bulk.Failed)+len(bulk.Rotated)))
}
