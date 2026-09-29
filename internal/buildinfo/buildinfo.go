// Package buildinfo exposes version information injected at link time.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// These are set with -ldflags "-X github.com/matusso/sslknife/internal/buildinfo.Version=...".
var (
	Version = "0.1.0-dev"
	Commit  = ""
	Date    = ""
)

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Built     string `json:"built"`
	GoVersion string `json:"go"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns build information, falling back to VCS data embedded by the Go
// toolchain when ldflags were not supplied.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		Built:     Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" && len(s.Value) >= 7 {
					info.Commit = s.Value[:7]
				}
			case "vcs.time":
				if info.Built == "" {
					info.Built = s.Value
				}
			}
		}
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.Built == "" {
		info.Built = "unknown"
	}
	return info
}
