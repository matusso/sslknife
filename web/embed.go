// Package web embeds the SSLKnife web interface: plain ES modules and CSS
// with no build step, served by `sslknife server`.
package web

import (
	"embed"
	"io/fs"
)

//go:embed static
var files embed.FS

// Static returns the asset file system (index.html, app.js, style.css).
func Static() fs.FS {
	sub, err := fs.Sub(files, "static")
	if err != nil {
		panic(err)
	}
	return sub
}
