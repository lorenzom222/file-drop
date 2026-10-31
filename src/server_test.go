package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixture struct {
	app    *app
	server *httptest.Server
	cookie *http.Cookie
	cancel context.CancelFunc
	clock  atomic.Int64
}

func setup(t *testing.T, edit func(*config)) *fixture {
	t.Helper()
	c := defaultConfig()
	c.Inbox = t.TempDir()
	c.FileLimit, c.Budget, c.FreeReserve = 1024, 8192, 0
	if edit != nil {
		edit(&c)
	}
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &fixture{cancel: cancel}
	f.clock.Store(time.Now().UnixNano())
	f.app = newApp(c, s, ctx)
	f.app.now = func() time.Time { return time.Unix(0, f.clock.Load()) }
	f.server = httptest.NewTLSServer(f.app.handler())
	f.app.cfg.PublicURL = f.server.URL
	t.Cleanup(func() {
		cancel()
		f.server.Close()
		if err := s.close(); err != nil {
			t.Error(err)
		}
	})
	response := f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+f.app.invitation+`"}`), "application/json", nil)
	defer response.Body.Close()
	if response.StatusCode != 200 || len(response.Cookies()) != 1 {
		t.Fatalf("session: %d", response.StatusCode)
	}
	f.cookie = response.Cookies()[0]
	return f
}

func (f *fixture) request(t *testing.T, path string, body io.Reader, contentType string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", f.server.URL+path, body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", f.server.URL)
	req.Header.Set("X-Filedrop-Request", "1")
	req.Header.Set("Content-Type", contentType)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	res, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func multipartBody(t *testing.T, name string, data []byte, extra bool) (*bytes.Buffer, string) {
	t.Helper()
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	part, err := w.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if extra {
		if err := w.WriteField("unexpected", "field"); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return &b, w.FormDataContentType()
}

func assertEmptyStage(t *testing.T, f *fixture) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(f.app.cfg.Inbox, ".filedrop-staging"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging not empty: %v %v", entries, err)
	}
}

func TestUploads(t *testing.T) {
	f := setup(t, nil)
	data := []byte("a receipt photo")
	names := []string{}
	for i := 0; i < 2; i++ {
		body, contentType := multipartBody(t, "receipt.jpg", data, false)
		res := f.request(t, "/api/uploads", body, contentType, f.cookie)
		var result struct {
			Name  string
			Bytes int64
		}
		if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 201 || result.Bytes != int64(len(data)) {
			t.Fatalf("upload: %d %#v", res.StatusCode, result)
		}
		stored, err := os.ReadFile(filepath.Join(f.app.cfg.Inbox, result.Name))
		if err != nil || !bytes.Equal(stored, data) {
			t.Fatalf("stored mismatch: %v", err)
		}
		names = append(names, result.Name)
	}
	if names[0] == names[1] {
		t.Fatal("collision overwrote existing file")
	}
	assertEmptyStage(t, f)
	if f.app.store.used != int64(2*len(data)) {
		t.Fatal("incorrect committed budget")
	}
	req, err := http.NewRequest("GET", f.server.URL+"/receipt.jpg", nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := f.server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatal("received file exposed through HTTP")
	}
}

func TestRejectedUploads(t *testing.T) {
	for _, tc := range []struct {
		name, filename string
		size           int
		extra, unauth  bool
		status         int
	}{
		{"traversal", "../outside.jpg", 3, false, false, 400},
		{"windows-path", `C:\outside.jpg`, 3, false, false, 400},
		{"reserved", "CON.txt", 3, false, false, 400},
		{"hidden", ".filedrop-lock", 3, false, false, 400},
		{"oversize", "big.jpg", 1025, false, false, 413},
		{"extra-part", "photo.jpg", 3, true, false, 400},
		{"unauthenticated", "photo.jpg", 3, false, true, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := setup(t, nil)
			body, ct := multipartBody(t, tc.filename, bytes.Repeat([]byte{1}, tc.size), tc.extra)
			cookie := f.cookie
			if tc.unauth {
				cookie = nil
			}
			res := f.request(t, "/api/uploads", body, ct, cookie)
			defer res.Body.Close()
			if res.StatusCode != tc.status {
				result, _ := io.ReadAll(res.Body)
				t.Fatalf("got %d want %d: %s", res.StatusCode, tc.status, result)
			}
			assertEmptyStage(t, f)
			if f.app.store.used != 0 {
				t.Fatal("failed upload consumed committed budget")
			}
		})
	}
}

func TestRequestBoundaries(t *testing.T) {
	f := setup(t, nil)
	for _, tc := range []struct{ origin, host, header string }{
		{"https://attacker.example", "", "1"},
		{"null", "", "1"},
		{"", "", "1"},
		{f.server.URL, "attacker.example", "1"},
		{f.server.URL, "", ""},
	} {
		req, err := http.NewRequest("POST", f.server.URL+"/api/session", strings.NewReader(`{}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("X-Filedrop-Request", tc.header)
		if tc.host != "" {
			req.Host = tc.host
		}
		res, err := f.server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if res.StatusCode != 403 || res.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Fatalf("boundary failed: %d", res.StatusCode)
		}
	}
	if !f.cookie.Secure || !f.cookie.HttpOnly || f.cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie attributes")
	}
}

func TestExpiration(t *testing.T) {
	f := setup(t, nil)
	f.clock.Add(int64(11 * time.Minute))
	res := f.request(t, "/api/session", strings.NewReader(`{"invitation":"`+f.app.invitation+`"}`), "application/json", nil)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("expired invitation accepted")
	}
	if !f.app.authorized(&http.Request{Header: http.Header{"Cookie": []string{f.cookie.String()}}}) {
		t.Fatal("invitation expiration revoked existing session")
	}
	f.clock.Add(int64(20 * time.Minute))
	body, ct := multipartBody(t, "expired.txt", []byte("test"), false)
	res = f.request(t, "/api/uploads", body, ct, f.cookie)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("expired session accepted")
	}
	assertEmptyStage(t, f)
}

func TestExpiredDuringUpload(t *testing.T) {
	f := setup(t, nil)
	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	started, finish := make(chan struct{}), make(chan struct{})
	go func() {
		defer pw.Close()
		part, err := writer.CreateFormFile("file", "expired.txt")
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		if _, err := part.Write([]byte("test")); err != nil {
			pw.CloseWithError(err)
			return
		}
		close(started)
		<-finish
		if err := writer.Close(); err != nil {
			pw.CloseWithError(err)
		}
	}()
	done := make(chan *http.Response, 1)
	go func() { done <- f.request(t, "/api/uploads", pr, writer.FormDataContentType(), f.cookie) }()
	<-started
	f.clock.Add(int64(31 * time.Minute))
	close(finish)
	res := <-done
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatalf("expired in-flight upload: %d", res.StatusCode)
	}
	assertEmptyStage(t, f)
}

func TestStorageConfinementAndBudget(t *testing.T) {
	f := setup(t, func(c *config) { c.Budget = 1024 })
	outside := filepath.Join(t.TempDir(), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(f.app.cfg.Inbox, "photo.txt")); err != nil {
		t.Fatal(err)
	}
	body, ct := multipartBody(t, "photo.txt", []byte("new"), false)
	res := f.request(t, "/api/uploads", body, ct, f.cookie)
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatalf("symlink collision: %d", res.StatusCode)
	}
	content, err := os.ReadFile(outside)
	if err != nil || string(content) != "keep" {
		t.Fatal("symlink target changed")
	}
	body, ct = multipartBody(t, "another.txt", []byte("new"), false)
	res = f.request(t, "/api/uploads", body, ct, f.cookie)
	res.Body.Close()
	if res.StatusCode != 507 {
		t.Fatal("reservation overcommitted budget")
	}
	assertEmptyStage(t, f)
}

func TestConcurrentReservations(t *testing.T) {
	f := setup(t, nil)
	var wg sync.WaitGroup
	var accepted atomic.Int64
	release := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.app.store.reserve() == nil {
				accepted.Add(1)
				<-release
				f.app.store.release(0)
			}
		}()
	}
	deadline := time.Now().Add(time.Second)
	for accepted.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	if accepted.Load() != 2 {
		t.Errorf("accepted %d concurrent reservations", accepted.Load())
	}
	close(release)
	wg.Wait()
}

func TestLowSpaceAndMalformed(t *testing.T) {
	f := setup(t, func(c *config) { c.FreeReserve = 1 << 60 })
	body, ct := multipartBody(t, "test.txt", []byte("test"), false)
	res := f.request(t, "/api/uploads", body, ct, f.cookie)
	res.Body.Close()
	if res.StatusCode != 507 {
		t.Fatal("disk floor not enforced")
	}
	assertEmptyStage(t, f)
	res = f.request(t, "/api/uploads", strings.NewReader("broken"), "multipart/form-data; boundary=test", f.cookie)
	res.Body.Close()
	if res.StatusCode != 400 {
		t.Fatal("malformed body accepted")
	}
}

func TestCanceledServerUpload(t *testing.T) {
	f := setup(t, nil)
	f.cancel()
	body, ct := multipartBody(t, "test.txt", []byte("test"), false)
	res := f.request(t, "/api/uploads", body, ct, f.cookie)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("shutdown did not revoke authorization")
	}
	assertEmptyStage(t, f)
}

func TestInboxLockAndStartupCleanup(t *testing.T) {
	c := defaultConfig()
	c.Inbox = t.TempDir()
	s, err := openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := openStore(c); err == nil {
		second.close()
		t.Fatal("two servers locked same inbox")
	}
	stage := ".filedrop-staging/upload-" + randomID()
	if err := os.WriteFile(filepath.Join(c.Inbox, stage), []byte("partial"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	s, err = openStore(c)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if _, err := os.Stat(filepath.Join(c.Inbox, stage)); !os.IsNotExist(err) {
		t.Fatal("stale upload survived cleanup")
	}
}

func TestSafeNames(t *testing.T) {
	for _, name := range []string{"../x", "/tmp/x", ".", "..", ".hidden", "a/b", `a\b`, "a:b", "NUL.txt", "COM1", "LPT9.txt", "trailing.", " space", "x\n.txt", "x\u202e.txt", strings.Repeat("a", 181)} {
		if safeName(name) {
			t.Errorf("accepted unsafe name %q", name)
		}
	}
	for _, name := range []string{"photo.jpg", "receipt 01.pdf", "café.txt"} {
		if !safeName(name) {
			t.Errorf("rejected safe name %q", name)
		}
	}
}

func TestConfig(t *testing.T) {
	valid := defaultConfig()
	valid.Inbox = t.TempDir()
	valid.DevHTTP = true
	valid.PublicURL = "http://127.0.0.1:8443"
	if _, err := valid.validate(); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*config){
		func(c *config) { c.Listen = "0.0.0.0:8443" },
		func(c *config) { c.Listen = "192.168.1.5:8443" },
		func(c *config) { c.PublicURL = "http://192.168.1.5:8443" },
		func(c *config) { c.PublicURL += "/path" },
		func(c *config) { c.Inbox = "relative" },
		func(c *config) { c.DevHTTP = false },
		func(c *config) { c.Concurrency = 3 },
	} {
		c := valid
		edit(&c)
		if _, err := c.validate(); err == nil {
			t.Fatal("unsafe config accepted")
		}
	}
	c := defaultConfig()
	c.Inbox = t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c.Cert, c.Key = filepath.Join(c.Inbox, "cert.pem"), filepath.Join(c.Inbox, "key.pem")
	if err := os.WriteFile(c.Cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.Key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
	tlsConfig, err := c.validate()
	if err != nil || tlsConfig == nil {
		t.Fatalf("valid TLS failed: %v", err)
	}
	c.PublicURL = "https://localhost:8443"
	if _, err := c.validate(); err == nil {
		t.Fatal("hostname mismatch accepted")
	}
}

type repeatedReader struct{}

func (repeatedReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i % 251)
	}
	return len(p), nil
}

func TestLargeConcurrentUploads(t *testing.T) {
	if os.Getenv("FILEDROP_LARGE") != "1" {
		t.Skip("set FILEDROP_LARGE=1 for two concurrent 1 GiB transfers")
	}
	size := int64(1 << 30)
	if value := os.Getenv("FILEDROP_LARGE_BYTES"); value != "" {
		var err error
		size, err = strconv.ParseInt(value, 10, 64)
		if err != nil || size < 1 || size > 1<<30 {
			t.Fatal("FILEDROP_LARGE_BYTES must be between 1 and 1073741824")
		}
	}
	f := setup(t, func(c *config) { c.FileLimit = 1 << 30; c.Budget = 5 << 30 })
	var wg sync.WaitGroup
	for _, name := range []string{"large-a.bin", "large-b.bin"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pr, pw := io.Pipe()
			writer := multipart.NewWriter(pw)
			sourceHash := sha256.New()
			writeDone := make(chan error, 1)
			go func() {
				part, err := writer.CreateFormFile("file", name)
				if err == nil {
					_, err = io.CopyBuffer(io.MultiWriter(part, sourceHash), io.LimitReader(repeatedReader{}, size), make([]byte, 64<<10))
				}
				if err == nil {
					err = writer.Close()
				}
				pw.CloseWithError(err)
				writeDone <- err
			}()
			res := f.request(t, "/api/uploads", pr, writer.FormDataContentType(), f.cookie)
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			if err := <-writeDone; err != nil {
				t.Error(err)
				return
			}
			if res.StatusCode != 201 {
				t.Errorf("large upload: %d", res.StatusCode)
				return
			}
			file, err := os.Open(filepath.Join(f.app.cfg.Inbox, name))
			if err != nil {
				t.Error(err)
				return
			}
			defer file.Close()
			destinationHash := sha256.New()
			received, err := io.Copy(destinationHash, file)
			if err != nil || received != size || !bytes.Equal(sourceHash.Sum(nil), destinationHash.Sum(nil)) {
				t.Errorf("large hash/size mismatch: %d %v", received, err)
			}
		}()
	}
	wg.Wait()
	assertEmptyStage(t, f)
}

func waitIdle(t *testing.T, f *fixture) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		f.app.store.mu.Lock()
		active := f.app.store.active
		f.app.store.mu.Unlock()
		if active == 0 {
			assertEmptyStage(t, f)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("upload handler did not stop")
}

func TestInterruptedUploads(t *testing.T) {
	for _, mode := range []string{"client-cancel", "timeout", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			f := setup(t, func(c *config) { c.UploadTimeout = 250 * time.Millisecond })
			pr, pw := io.Pipe()
			defer pr.Close()
			defer pw.Close()
			writer := multipart.NewWriter(pw)
			started := make(chan struct{})
			go func() {
				part, err := writer.CreateFormFile("file", "interrupted.txt")
				if err == nil {
					_, err = part.Write([]byte("partial"))
				}
				if err != nil {
					pw.CloseWithError(err)
				}
				close(started)
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, "POST", f.server.URL+"/api/uploads", pr)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Origin", f.server.URL)
			req.Header.Set("X-Filedrop-Request", "1")
			req.Header.Set("Content-Type", writer.FormDataContentType())
			req.AddCookie(f.cookie)
			done := make(chan error, 1)
			go func() {
				res, err := f.server.Client().Do(req)
				if err == nil {
					res.Body.Close()
					if res.StatusCode == 201 {
						err = io.ErrUnexpectedEOF
					}
				}
				done <- err
			}()
			<-started
			for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
				entries, err := os.ReadDir(filepath.Join(f.app.cfg.Inbox, ".filedrop-staging"))
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) > 0 {
					break
				}
				time.Sleep(time.Millisecond)
			}
			switch mode {
			case "client-cancel":
				cancel()
				pw.CloseWithError(context.Canceled)
			case "shutdown":
				f.cancel()
			}
			select {
			case err := <-done:
				if err == io.ErrUnexpectedEOF {
					t.Fatal("interrupted upload reported success")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("interrupted request did not return")
			}
			waitIdle(t, f)
			if _, err := os.Stat(filepath.Join(f.app.cfg.Inbox, "interrupted.txt")); !os.IsNotExist(err) {
				t.Fatal("partial file was published")
			}
		})
	}
}

func TestOversizedMultipartHeaders(t *testing.T) {
	f := setup(t, nil)
	data := "--test\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.txt\"\r\nX-Padding: " + strings.Repeat("a", 70<<10) + "\r\n\r\ndata\r\n--test--\r\n"
	res := f.request(t, "/api/uploads", strings.NewReader(data), "multipart/form-data; boundary=test", f.cookie)
	res.Body.Close()
	if res.StatusCode == 201 {
		t.Fatal("oversized multipart header accepted")
	}
	assertEmptyStage(t, f)
}

func TestStorageWriteFailure(t *testing.T) {
	f := setup(t, nil)
	stage := filepath.Join(f.app.cfg.Inbox, ".filedrop-staging")
	if err := os.Chmod(stage, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(stage, 0700)
	body, ct := multipartBody(t, "test.txt", []byte("test"), false)
	res := f.request(t, "/api/uploads", body, ct, f.cookie)
	res.Body.Close()
	if res.StatusCode != 500 {
		t.Fatalf("storage failure: %d", res.StatusCode)
	}
	assertEmptyStage(t, f)
}
