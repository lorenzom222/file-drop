package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestLocalFontAssets(t *testing.T) {
	f := setup(t, nil)
	for _, tc := range []struct {
		path, contentType, marker string
	}{
		{"/fonts/jetbrains-mono.woff2", "font/woff2", "wOF2"},
		{"/fonts/OFL.txt", "text/plain; charset=utf-8", "SIL OPEN FONT LICENSE"},
		{"/style.css", "text/css; charset=utf-8", `font-family: "JetBrains Mono"`},
	} {
		res, err := f.server.Client().Get(f.server.URL + tc.path)
		if err != nil {
			t.Fatal(err)
		}
		data, readErr := io.ReadAll(res.Body)
		closeErr := res.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("asset read failed: %v %v", readErr, closeErr)
		}
		if res.StatusCode != 200 || res.Header.Get("Content-Type") != tc.contentType || !bytes.Contains(data, []byte(tc.marker)) {
			t.Fatalf("invalid asset response for %s: %d %s", tc.path, res.StatusCode, res.Header.Get("Content-Type"))
		}
		if !strings.Contains(res.Header.Get("Content-Security-Policy"), "font-src 'self'") {
			t.Fatal("local font blocked by content security policy")
		}
	}
}
