package web

import (
	"bytes"
	"embed"
	"net/url"
)

var Version = "dev"

// Files contains the browser application served by the Go process.
//
//go:embed static/*
var Files embed.FS

func IndexHTML() ([]byte, error) {
	data, err := Files.ReadFile("static/index.html")
	if err != nil {
		return nil, err
	}
	version := url.QueryEscape(Version)
	data = bytes.ReplaceAll(data, []byte(`/static/app.css`), []byte(`/static/app.css?v=`+version))
	data = bytes.ReplaceAll(data, []byte(`/static/app.js`), []byte(`/static/app.js?v=`+version))
	return data, nil
}
