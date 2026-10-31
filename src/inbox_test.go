package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func viewCookie(t *testing.T, f *fixture) *http.Cookie {
	t.Helper()
	res := f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+f.app.viewInvitation+`"}`), "application/json", nil)
	defer res.Body.Close()
	var result struct {
		CanViewInbox bool `json:"can_view_inbox"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !result.CanViewInbox || len(res.Cookies()) != 1 {
		t.Fatalf("view invitation: %d %#v", res.StatusCode, result)
	}
	return res.Cookies()[0]
}

func getInbox(t *testing.T, f *fixture, cookie *http.Cookie, origin, site, host, custom string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", f.server.URL+"/api/inbox", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Set("X-Filedrop-Request", custom)
	if host != "" {
		req.Host = host
	}
	res, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func readInbox(t *testing.T, f *fixture, cookie *http.Cookie) []inboxFile {
	t.Helper()
	res := getInbox(t, f, cookie, "", "same-origin", "", "1")
	defer res.Body.Close()
	var result struct {
		Files []inboxFile `json:"files"`
	}
	if res.StatusCode != 200 {
		t.Fatalf("inbox: %d", res.StatusCode)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("listing can be cached")
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Files == nil {
		t.Fatal("empty listing must be [] not null")
	}
	return result.Files
}

func TestInboxPermissions(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			f := setup(t, func(c *config) { c.ShareInbox = enabled })
			for _, cookie := range []*http.Cookie{nil, f.cookie} {
				res := getInbox(t, f, cookie, "", "same-origin", "", "1")
				res.Body.Close()
				want := 403
				if cookie == nil {
					want = 401
				}
				if res.StatusCode != want {
					t.Fatalf("upload-only listing: got %d want %d", res.StatusCode, want)
				}
			}
			if enabled {
				cookie := viewCookie(t, f)
				if len(readInbox(t, f, cookie)) != 0 {
					t.Fatal("new inbox is not empty")
				}
				res := getInbox(t, f, f.cookie, "", "same-origin", "", "1")
				res.Body.Close()
				if res.StatusCode != 403 {
					t.Fatal("existing upload session gained viewing permission")
				}
				// A client cannot request its own permission upgrade.
				res = f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+f.app.invitation+`","can_view_inbox":true}`), "application/json", nil)
				res.Body.Close()
				if res.StatusCode != 400 {
					t.Fatal("client granted itself view access")
				}
				f.clock.Add(int64(31 * time.Minute))
				res = getInbox(t, f, cookie, "", "same-origin", "", "1")
				res.Body.Close()
				if res.StatusCode != 401 {
					t.Fatal("expired viewer retained access")
				}
			}
		})
	}
}

func TestInboxSnapshotAndUpload(t *testing.T) {
	f := setup(t, func(c *config) { c.ShareInbox = true })
	cookie := viewCookie(t, f)
	root := f.app.cfg.Inbox
	for _, name := range []string{"old.txt", "new.txt", ".hidden", ".filedrop-staging/upload-" + randomID()} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(root, "old.txt"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "subfolder"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "subfolder", "secret.txt"), []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "old.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Join(root, "directory-link")); err != nil {
		t.Fatal(err)
	}
	files := readInbox(t, f, cookie)
	if len(files) != 2 || files[0].Name != "new.txt" || files[1].Name != "old.txt" || files[1].Bytes != 4 || !files[1].ModifiedAt.Equal(old) {
		t.Fatalf("unexpected snapshot: %#v", files)
	}
	body, ct := multipartBody(t, "uploaded.txt", []byte("upload"), false)
	res := f.request(t, "/api/uploads", body, ct, cookie)
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatalf("view invite lost upload permission: %d", res.StatusCode)
	}
	files = readInbox(t, f, cookie)
	if len(files) != 3 || files[0].Name != "uploaded.txt" {
		t.Fatalf("upload not visible: %#v", files)
	}
	if err := os.Remove(filepath.Join(root, "uploaded.txt")); err != nil {
		t.Fatal(err)
	}
	if files := readInbox(t, f, cookie); len(files) != 2 {
		t.Fatal("listing did not reflect deletion")
	}
	res, err := f.server.Client().Get(f.server.URL + "/uploaded.txt")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatal("metadata listing exposed downloads")
	}
}

func TestInboxRequestBoundaries(t *testing.T) {
	f := setup(t, func(c *config) { c.ShareInbox = true })
	cookie := viewCookie(t, f)
	for _, tc := range []struct{ origin, site, host, custom string }{
		{"https://attacker.example", "same-origin", "", "1"},
		{"null", "same-origin", "", "1"},
		{"", "cross-site", "", "1"},
		{"", "same-site", "", "1"},
		{"", "same-origin", "attacker.example", "1"},
		{"", "same-origin", "", ""},
	} {
		res := getInbox(t, f, cookie, tc.origin, tc.site, tc.host, tc.custom)
		res.Body.Close()
		if res.StatusCode != 403 {
			t.Fatalf("hostile listing request: %#v returned %d", tc, res.StatusCode)
		}
	}
}

func TestInboxListingLimitsAndErrors(t *testing.T) {
	f := setup(t, func(c *config) { c.ShareInbox = true })
	cookie := viewCookie(t, f)
	for i := 0; i < inboxEntryLimit; i++ {
		file, err := f.app.store.root.OpenFile("file-"+strconv.Itoa(i), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	res := getInbox(t, f, cookie, "", "same-origin", "", "1")
	res.Body.Close()
	if res.StatusCode != 409 {
		t.Fatal("unbounded listing accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := f.app.store.listInbox(ctx); !errors.Is(err, errInboxLimit) && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected context/limit error: %v", err)
	}
	// A failed directory read must not look like a successful empty inbox.
	if err := os.Chmod(f.app.cfg.Inbox, 0100); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(f.app.cfg.Inbox, 0700)
	res = getInbox(t, f, cookie, "", "same-origin", "", "1")
	res.Body.Close()
	if res.StatusCode != 500 {
		t.Fatalf("read failure not surfaced: %d", res.StatusCode)
	}
}
