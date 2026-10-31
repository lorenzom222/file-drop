package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func downloadCookie(t *testing.T, f *fixture) *http.Cookie {
	t.Helper()
	res := f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+f.app.downloadInvitation+`"}`), "application/json", nil)
	defer res.Body.Close()
	var result struct {
		CanDownload bool `json:"can_download"`
		CanView     bool `json:"can_view_inbox"`
	}
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !result.CanDownload || !result.CanView || len(res.Cookies()) != 1 {
		t.Fatalf("download session: %d %#v", res.StatusCode, result)
	}
	return res.Cookies()[0]
}

func setupDownloads(t *testing.T) (*fixture, *http.Cookie, string) {
	t.Helper()
	f := setup(t, func(c *config) { c.ShareInbox = true; c.AllowDownloads = true })
	cookie := downloadCookie(t, f)
	body, ct := multipartBody(t, "document.txt", []byte("download these bytes"), false)
	res := f.request(t, "/api/uploads", body, ct, cookie)
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatalf("test upload: %d", res.StatusCode)
	}
	files := readInbox(t, f, cookie)
	if len(files) != 1 || files[0].ID == "" {
		t.Fatal("listing did not provide authorized download offer")
	}
	return f, cookie, files[0].ID
}

func getDownload(t *testing.T, f *fixture, cookie *http.Cookie, id, origin, site, rangeValue string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", f.server.URL+"/api/downloads/"+id, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Sec-Fetch-Site", site)
	req.Header.Set("Range", rangeValue)
	res, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestAuthenticatedDownload(t *testing.T) {
	f, cookie, id := setupDownloads(t)
	res := getDownload(t, f, cookie, id, "", "same-origin", "")
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != 200 || string(data) != "download these bytes" {
		t.Fatalf("download failed: %d %q %v", res.StatusCode, data, err)
	}
	if !strings.HasPrefix(res.Header.Get("Content-Disposition"), "attachment;") || res.Header.Get("Content-Type") != "application/octet-stream" || res.Header.Get("Cache-Control") != "no-store" || res.ContentLength != int64(len(data)) {
		t.Fatalf("unsafe download headers: %#v", res.Header)
	}
}

func TestDownloadPermissions(t *testing.T) {
	f, cookie, id := setupDownloads(t)
	viewer := viewCookie(t, f)
	if files := readInbox(t, f, viewer); files[0].ID != "" {
		t.Fatal("metadata viewer received a download offer")
	}
	other := downloadCookie(t, f)
	for _, tc := range []struct {
		cookie                       *http.Cookie
		id, origin, site, rangeValue string
		status                       int
	}{
		{nil, id, "", "same-origin", "", 401},
		{f.cookie, id, "", "same-origin", "", 403},
		{viewer, id, "", "same-origin", "", 403},
		{other, id, "", "same-origin", "", 403},
		{cookie, id + "tampered", "", "same-origin", "", 403},
		{cookie, id, "https://attacker.example", "same-origin", "", 403},
		{cookie, id, "", "cross-site", "", 403},
		{cookie, id, "", "same-origin", "bytes=0-1", 416},
	} {
		res := getDownload(t, f, tc.cookie, tc.id, tc.origin, tc.site, tc.rangeValue)
		res.Body.Close()
		if res.StatusCode != tc.status {
			t.Fatalf("permission case: got %d want %d", res.StatusCode, tc.status)
		}
	}
	f.clock.Add(int64(31 * time.Minute))
	res := getDownload(t, f, cookie, id, "", "same-origin", "")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("expired session downloaded file")
	}
}

func TestChangedDownloadSource(t *testing.T) {
	for _, mode := range []string{"modified", "replaced", "symlink", "fifo", "deleted"} {
		t.Run(mode, func(t *testing.T) {
			f, cookie, id := setupDownloads(t)
			path := filepath.Join(f.app.cfg.Inbox, "document.txt")
			if mode == "modified" {
				if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "replaced":
					if err := os.WriteFile(path, []byte("different object"), 0600); err != nil {
						t.Fatal(err)
					}
				case "symlink":
					target := filepath.Join(t.TempDir(), "private.txt")
					if err := os.WriteFile(target, []byte("not offered"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(path, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			res := getDownload(t, f, cookie, id, "", "same-origin", "")
			res.Body.Close()
			if res.StatusCode != 409 {
				t.Fatalf("changed source %s: %d", mode, res.StatusCode)
			}
		})
	}
}

func TestDownloadLimitsAndCancellation(t *testing.T) {
	f, cookie, id := setupDownloads(t)
	for i := 0; i < cap(f.app.downloadSlots); i++ {
		f.app.downloadSlots <- struct{}{}
	}
	res := getDownload(t, f, cookie, id, "", "same-origin", "")
	res.Body.Close()
	if res.StatusCode != 429 {
		t.Fatal("download concurrency limit bypassed")
	}
	for i := 0; i < cap(f.app.downloadSlots); i++ {
		<-f.app.downloadSlots
	}
	req, err := http.NewRequest("GET", f.server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	var destination bytes.Buffer
	writer := downloadWriter{app: f.app, request: req, ctx: context.Background(), writer: &destination}
	if _, err := writer.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	f.clock.Add(int64(31 * time.Minute))
	if _, err := writer.Write([]byte("forbidden")); err != errDownloadCanceled || destination.String() != "first" {
		t.Fatal("expired download continued writing")
	}
}

func TestDownloadConfigAndOffer(t *testing.T) {
	c := defaultConfig()
	c.AllowDownloads = true
	if _, err := c.validate(); err == nil {
		t.Fatal("downloads enabled without explicit inbox sharing")
	}
	file := inboxFile{Name: "safe.txt", Bytes: 3, ModifiedAt: time.Now(), identity: fileIdentity{Device: 1, Inode: 2}}
	id, err := signOffer("test-key", file)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := verifyOffer("test-key", id)
	if err != nil || offer.Name != file.Name || offer.Identity != file.identity {
		t.Fatalf("offer roundtrip: %#v %v", offer, err)
	}
	if _, err := verifyOffer("another-session", id); err == nil {
		t.Fatal("offer usable by another session")
	}
	if _, err := verifyOffer("test-key", strings.Repeat("a", 1025)); err == nil {
		t.Fatal("oversized offer accepted")
	}
}

func TestLargeDownload(t *testing.T) {
	if os.Getenv("FILEDROP_LARGE") != "1" {
		t.Skip("set FILEDROP_LARGE=1 for a streaming 1 GiB download")
	}
	f := setup(t, func(c *config) { c.ShareInbox = true; c.AllowDownloads = true })
	file, err := os.Create(filepath.Join(f.app.cfg.Inbox, "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	sourceHash := sha256.New()
	if _, err := io.CopyBuffer(io.MultiWriter(file, sourceHash), io.LimitReader(repeatedReader{}, 1<<30), make([]byte, 64<<10)); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	cookie := downloadCookie(t, f)
	files := readInbox(t, f, cookie)
	res := getDownload(t, f, cookie, files[0].ID, "", "same-origin", "")
	defer res.Body.Close()
	hash := sha256.New()
	n, err := io.Copy(hash, res.Body)
	if err != nil || res.StatusCode != 200 || n != 1<<30 || !bytes.Equal(hash.Sum(nil), sourceHash.Sum(nil)) {
		t.Fatalf("large download mismatch: %d %d %v", res.StatusCode, n, err)
	}
}
