package web

import (
	"bytes"
	"testing"
)

func TestIndexHTMLAddsBuildVersionToStaticAssets(t *testing.T) {
	previous := Version
	Version = "1.2.3-test"
	t.Cleanup(func() { Version = previous })

	data, err := IndexHTML()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte("/static/app.css?v=1.2.3-test")) {
		t.Fatalf("stylesheet is not versioned: %s", data)
	}
	if !bytes.Contains(data, []byte("/static/app.js?v=1.2.3-test")) {
		t.Fatalf("script is not versioned: %s", data)
	}
}
