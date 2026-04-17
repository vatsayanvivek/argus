package main

import (
	"github.com/vatsayanvivek/argus/cmd"
)

// Version is set at build time via -ldflags="-X main.Version=<version>".
var Version = "1.1.0"

func main() {
	cmd.SetVersion(Version)
	cmd.Execute()
}
