package config_test

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"testing"
)

// The console shows how to connect each SIEM (console/src/siemSetup.ts) from a list of its
// own, as it never reads the server's settings. It must name exactly the settings Load reads.
func TestConsoleSIEMHelpNamesTheSettingsTheServerReads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	names := regexp.MustCompile(`ALTIWARD_(?:SPLUNK|SENTINEL|SYSLOG)_[A-Z_]+`)
	read := func(path string) []string {
		b, err := os.ReadFile(filepath.Join(filepath.Dir(file), path))
		if err != nil {
			t.Fatal(err)
		}
		found := names.FindAllString(string(b), -1)
		slices.Sort(found)
		return slices.Compact(found)
	}
	server, console := read("config.go"), read("../../../console/src/siemSetup.ts")
	if len(server) < 10 || !slices.Equal(server, console) {
		t.Fatalf("console/src/siemSetup.ts names %v, but the server reads %v", console, server)
	}
}
