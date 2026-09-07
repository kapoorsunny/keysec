package cmd

import (
	"context"
	"runtime"
	"runtime/debug"

	"github.com/kapoorsunny/keysec/internal/machine"
)

// Version implements "keysec version" (and "keysec --version").
//
// The version comes from the build information Go stamps into the
// binary: a build at a tagged commit records that tag, so releases need
// no -ldflags and the hand-built and CI release paths cannot drift
// apart. A build from an untagged or dirty tree says so rather than
// claiming to be a release — which matters when the answer decides
// whether a run log can still be read.
func (a *App) Version(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return machine.Usage("usage: keysec version", "--json for machine output")
	}
	b := buildInfo()
	if a.ui.InJSON() {
		return a.ui.JSON(b)
	}
	a.ui.Outln("keysec %s", b.Version)
	if b.Revision != "" {
		rev := b.Revision
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if b.Modified {
			rev += " (with uncommitted changes)"
		}
		a.ui.Hint("commit %s", rev)
	}
	a.ui.Hint("%s %s/%s", b.Go, b.OS, b.Arch)
	return nil
}

// buildInfo reads what the toolchain recorded at build time. Everything
// is best-effort: a binary built in a way that carries no build info
// still reports its platform rather than failing.
func buildInfo() machine.BuildInfo {
	b := machine.BuildInfo{
		Version: "unknown",
		Go:      runtime.Version(),
		OS:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	// "(devel)" is the toolchain's placeholder for a build that is not at
	// a tagged commit; the revision below is the only honest identifier
	// there, so do not present the placeholder as a version.
	if v := info.Main.Version; v != "" && v != "(devel)" {
		b.Version = v
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			b.Revision = s.Value
		case "vcs.modified":
			b.Modified = s.Value == "true"
		}
	}
	return b
}
