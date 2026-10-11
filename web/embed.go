// Package web embeds the browser UI into the binary.
package web

import "embed"

//go:embed index.html about.html
var FS embed.FS
