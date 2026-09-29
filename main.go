// Command sslknife is a Swiss-army knife for TLS, X.509, PKI and SSH keys.
package main

import (
	"os"

	"github.com/matusso/sslknife/cmd"
)

func main() {
	os.Exit(cmd.Execute(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
