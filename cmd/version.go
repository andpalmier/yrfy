package cmd

import (
	"fmt"
	"runtime/debug"
)

var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func executeVersion(args []string) error {
	fmt.Printf("yrfy version %s\n", Version)
	fmt.Printf("  commit: %s\n", Commit)
	fmt.Printf("  built: %s\n", BuildDate)
	return nil
}

// shortHashLength matches the abbreviation git uses by default, so a commit
// recovered from the build info reads the same as one passed by -ldflags.
const shortHashLength = 7

// init recovers the build information that -ldflags did not supply.
//
// "go install module@version" applies no -ldflags at all, so a binary installed
// the way the README describes reported itself as "dev" with no way to tell
// which release it came from. The toolchain does record the module version in
// that case, and records the revision and commit time instead when building
// inside a checkout, so between the two the binary can always say where it came
// from. Values that -ldflags did set are left alone.
func init() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	// "(devel)" is what a build from a working tree reports, which says less
	// than the revision below.
	if Version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if Commit == "unknown" && len(s.Value) >= shortHashLength {
				Commit = s.Value[:shortHashLength]
			}
		case "vcs.time":
			if BuildDate == "unknown" {
				BuildDate = s.Value
			}
		}
	}
}
