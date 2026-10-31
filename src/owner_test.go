package main

import (
	"bytes"
	"encoding/json"
	"image/png"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type ownerFixture struct {
	f          *fixture
	server     *httptest.Server
	credential string
	bootstrap  string
}

func setupOwner(t *testing.T, view, download bool) *ownerFixture {
	t.Helper()
	f := setup(t, func(c *config) { c.OwnerListen = "127.0.0.1:18445"; c.ShareInbox = view; c.AllowDownloads = download })
	server := httptest.NewServer(f.app.ownerHandler())
	f.app.cfg.OwnerListen = strings.TrimPrefix(server.URL, "http://")
	t.Cleanup(server.Close)
	o := &ownerFixture{f: f, server: server, bootstrap: f.app.ownerBootstrap}
	res := o.request(t, "/api/owner/session", map[string]string{"bootstrap": f.app.ownerBootstrap}, "")
	defer res.Body.Close()
	var result struct {
		Credential string `json:"credential"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || result.Credential == "" {
		t.Fatalf("owner bootstrap: %d", res.StatusCode)
	}
	o.credential = result.Credential
	return o
}

func (o *ownerFixture) request(t *testing.T, path string, body any, credential string) *http.Response {
	t.Helper()
	method := "GET"
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
		method = "POST"
	}
	req, err := http.NewRequest(method, o.server.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Filedrop-Request", "1")
	req.Header.Set("Origin", o.server.URL)
	req.Header.Set("Content-Type", "application/json")
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	res, err := o.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ownerLink(t *testing.T, o *ownerFixture, permission string) (string, time.Time) {
	t.Helper()
	res := o.request(t, "/api/owner/invitations", map[string]string{"permission": permission}, o.credential)
	defer res.Body.Close()
	var result struct {
		URL     string    `json:"url"`
		Expires time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("create link: %d", res.StatusCode)
	}
	u, err := url.Parse(result.URL)
	if err != nil || u.Fragment == "" || strings.TrimSuffix(result.URL, "/#"+u.Fragment) != o.f.app.cfg.PublicURL {
		t.Fatalf("bad link: %q %v", result.URL, err)
	}
	return u.Fragment, result.Expires
}

func TestOwnerInvitationLifecycle(t *testing.T) {
	o := setupOwner(t, true, true)
	initial := o.f.app.downloadInvitation
	o.f.clock.Add(int64(11 * time.Minute))
	token, end := ownerLink(t, o, "download")
	if end.Sub(o.f.app.now()) != 10*time.Minute || token == initial {
		t.Fatal("invitation was not renewed")
	}
	res := o.f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+token+`"}`), "application/json", nil)
	cookies := res.Cookies()
	var result struct {
		View     bool `json:"can_view_inbox"`
		Download bool `json:"can_download"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || !result.View || !result.Download || len(cookies) != 1 {
		t.Fatal("renewed scope missing")
	}
	next, _ := ownerLink(t, o, "download")
	if next == token {
		t.Fatal("renewal reused secret")
	}
	res = o.f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+token+`"}`), "application/json", nil)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("old invitation still accepts new sessions")
	}
	res = getInbox(t, o.f, cookies[0], "", "same-origin", "", "1")
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("rotation revoked existing scoped guest")
	}
	res = getInbox(t, o.f, o.f.cookie, "", "same-origin", "", "1")
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("upload-only session gained permissions")
	}
	o.f.clock.Add(int64(11 * time.Minute))
	res = o.f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+next+`"}`), "application/json", nil)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("expired regenerated invite accepted")
	}
}

func TestOwnerAuthorization(t *testing.T) {
	o := setupOwner(t, true, true)
	for _, credential := range []string{"", o.f.cookie.Value, "forged"} {
		res := o.request(t, "/api/owner/invitations", map[string]string{"permission": "download"}, credential)
		res.Body.Close()
		if res.StatusCode != 401 {
			t.Fatalf("nonowner authorized: %d", res.StatusCode)
		}
	}
	res := o.request(t, "/api/owner/session", map[string]string{"bootstrap": o.bootstrap}, "")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("consumed bootstrap replay accepted")
	}
	for _, path := range []string{"/owner.js", "/api/owner/status", "/api/owner/invitations"} {
		res, err := o.f.server.Client().Get(o.f.server.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 404 {
			t.Fatalf("owner surface exposed to guests: %s %d", path, res.StatusCode)
		}
	}
	o.f.clock.Add(int64(8 * time.Hour))
	res = o.request(t, "/api/owner/status", nil, o.credential)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("owner session did not expire")
	}
}

func TestOwnerRequestBoundaries(t *testing.T) {
	o := setupOwner(t, true, true)
	for _, tc := range []struct{ origin, host, marker, site string }{
		{"https://attacker.example", "", "1", ""},
		{"null", "", "1", ""},
		{"", "", "1", ""},
		{o.server.URL, "attacker.example", "1", ""},
		{o.server.URL, "", "", ""},
		{o.server.URL, "", "1", "cross-site"},
		{o.server.URL, "", "1", "same-site"},
	} {
		req, err := http.NewRequest("POST", o.server.URL+"/api/owner/invitations", strings.NewReader(`{"permission":"download"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("X-Filedrop-Request", tc.marker)
		req.Header.Set("Sec-Fetch-Site", tc.site)
		req.Header.Set("Authorization", "Bearer "+o.credential)
		if tc.host != "" {
			req.Host = tc.host
		}
		res, err := o.server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("hostile owner request: %d", res.StatusCode)
		}
	}
	res := o.request(t, "/api/owner/invitations", map[string]any{"permission": "download", "can_download": true}, o.credential)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatal("unexpected owner payload accepted")
	}
	res = o.request(t, "/api/owner/invitations", map[string]any{"permission": strings.Repeat("a", 2048)}, o.credential)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatal("oversized owner payload accepted")
	}
}

func TestOwnerEnabledPermissions(t *testing.T) {
	o := setupOwner(t, false, false)
	for _, permission := range []string{"view", "download", "invalid"} {
		res := o.request(t, "/api/owner/invitations", map[string]string{"permission": permission}, o.credential)
		res.Body.Close()
		want := 403
		if permission == "invalid" {
			want = 400
		}
		if res.StatusCode != want {
			t.Fatalf("disabled scope accepted: %d", res.StatusCode)
		}
	}
	token, _ := ownerLink(t, o, "upload")
	res := o.f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+token+`"}`), "application/json", nil)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("upload-only linking failed")
	}
}

func TestOwnerQR(t *testing.T) {
	o := setupOwner(t, true, true)
	token, _ := ownerLink(t, o, "upload")
	payload := map[string]string{"permission": "upload", "invitation": token}
	res := o.request(t, "/api/owner/qr", payload, o.credential)
	defer res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "image/png" || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("QR failed: %d", res.StatusCode)
	}
	img, err := png.Decode(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != img.Bounds().Dy() || img.Bounds().Dx() < 100 {
		t.Fatal("bad QR dimensions")
	}
	_, _, _, alpha := img.At(0, 0).RGBA()
	red, green, blue, _ := img.At(0, 0).RGBA()
	if alpha != 65535 || red != 65535 || green != 65535 || blue != 65535 {
		t.Fatal("QR quiet zone not white")
	}
	if payload["invitation"] == "" {
		t.Fatal("missing QR token")
	}
	ownerLink(t, o, "upload")
	res = o.request(t, "/api/owner/qr", payload, o.credential)
	res.Body.Close()
	if res.StatusCode != 410 {
		t.Fatal("QR silently substituted a different invitation")
	}
}

func TestOwnerListenerConfig(t *testing.T) {
	c := defaultConfig()
	c.DevHTTP = true
	c.PublicURL = "http://127.0.0.1:8443"
	c.Inbox = t.TempDir()
	for _, listen := range []string{"192.168.1.5:18445", "0.0.0.0:18445", "127.0.0.1:0", c.Listen, "localhost:18445"} {
		c.OwnerListen = listen
		if _, err := c.validate(); err == nil {
			t.Fatalf("unsafe owner binding: %s", listen)
		}
	}
	c.OwnerListen = "[::1]:18445"
	if _, err := c.validate(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerBootstrapExpiry(t *testing.T) {
	f := setup(t, func(c *config) { c.OwnerListen = "127.0.0.1:18445" })
	server := httptest.NewServer(f.app.ownerHandler())
	defer server.Close()
	f.app.cfg.OwnerListen = strings.TrimPrefix(server.URL, "http://")
	o := &ownerFixture{f: f, server: server}
	f.clock.Add(int64(11 * time.Minute))
	res := o.request(t, "/api/owner/session", map[string]string{"bootstrap": f.app.ownerBootstrap}, "")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("expired owner bootstrap accepted")
	}
}
