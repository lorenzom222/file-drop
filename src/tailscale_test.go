package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTailscaleServeConfig(t *testing.T) {
	c := defaultConfig()
	c.Inbox = t.TempDir()
	c.TailscaleServe = true
	c.PublicURL = "https://receiver.example-tailnet.ts.net"
	tlsConfig, err := c.validate()
	if err != nil || tlsConfig != nil {
		t.Fatalf("valid proxy config: %v", err)
	}
	for _, edit := range []func(*config){
		func(c *config) { c.DevHTTP = true },
		func(c *config) { c.Listen = "192.168.1.50:8443" },
		func(c *config) { c.Listen = "100.64.1.2:8443" },
		func(c *config) { c.Listen = "0.0.0.0:8443" },
		func(c *config) { c.PublicURL = "http://receiver.example-tailnet.ts.net" },
		func(c *config) { c.PublicURL = "https://attacker.example" },
		func(c *config) { c.PublicURL += ":443" },
		func(c *config) { c.PublicURL += "/" },
		func(c *config) { c.Cert = "unused.pem" },
		func(c *config) { c.Key = "unused.key" },
	} {
		invalid := c
		edit(&invalid)
		if _, err := invalid.validate(); err == nil {
			t.Fatalf("invalid proxy config accepted: %#v", invalid)
		}
	}
	c.Listen = "[::1]:8443"
	if _, err := c.validate(); err != nil {
		t.Fatalf("IPv6 loopback rejected: %v", err)
	}
}

func TestHTTPSProxyUpload(t *testing.T) {
	c := defaultConfig()
	c.TailscaleServe = true
	c.PublicURL = "https://receiver.example-tailnet.ts.net"
	c.Inbox = t.TempDir()
	c.FileLimit, c.Budget, c.FreeReserve = 1024, 8192, 0
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.close(); err != nil {
			t.Error(err)
		}
	})
	a := newApp(c, s, context.Background())
	backend := httptest.NewServer(a.handler())
	defer backend.Close()
	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	// Like Serve's TCP proxy, preserve the original Host while targeting loopback.
	proxy := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	defer proxy.Close()
	request := func(path string, body io.Reader, ct, host, origin string, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, err := http.NewRequest("POST", proxy.URL+path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Host = host
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", ct)
		req.Header.Set("X-Filedrop-Request", "1")
		req.Header.Set("X-Forwarded-Host", "receiver.example-tailnet.ts.net")
		req.Header.Set("Tailscale-User-Login", "claimed-user@example.test")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		res, err := proxy.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	host := "receiver.example-tailnet.ts.net"
	res := request("/api/session", strings.NewReader(`{"invitation":"`+a.invitation+`"}`), "application/json", host, c.PublicURL, nil)
	res.Body.Close()
	if res.StatusCode != 200 || len(res.Cookies()) != 1 {
		t.Fatalf("proxy session: %d", res.StatusCode)
	}
	cookie := res.Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("HTTPS proxy mode weakened session cookie")
	}
	data := []byte("file sent through an HTTPS proxy")
	body, ct := multipartBody(t, "proxy.txt", data, false)
	res = request("/api/uploads", body, ct, host, c.PublicURL, cookie)
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatalf("proxy upload: %d", res.StatusCode)
	}
	saved, err := os.ReadFile(filepath.Join(c.Inbox, "proxy.txt"))
	if err != nil || !bytes.Equal(saved, data) {
		t.Fatalf("saved bytes mismatch: %v", err)
	}
	for _, tc := range []struct {
		host, origin string
		cookie       *http.Cookie
		status       int
	}{
		{host, c.PublicURL, nil, 401},
		{"attacker.example", c.PublicURL, cookie, 403},
		{host, "https://attacker.example", cookie, 403},
		{"127.0.0.1:8443", c.PublicURL, cookie, 403},
	} {
		body, ct = multipartBody(t, "blocked.txt", data, false)
		res = request("/api/uploads", body, ct, tc.host, tc.origin, tc.cookie)
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("proxy boundary: got %d want %d", res.StatusCode, tc.status)
		}
	}
}
