package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed ui/index.html ui/style.css ui/dist/app.js ui/fonts/jetbrains-mono.woff2 ui/fonts/OFL.txt
var assets embed.FS

const cookieName = "filedrop_session"

type uploadSession struct {
	expiresAt   time.Time
	viewInbox   bool
	canDownload bool
	offerKey    string
}

type app struct {
	cfg                config
	store              *store
	invitation         string
	viewInvitation     string
	downloadInvitation string
	inviteEnd          time.Time
	mu                 sync.Mutex
	sessions           map[string]uploadSession
	now                func() time.Time
	ctx                context.Context
	downloadSlots      chan struct{}
}

func newApp(c config, s *store, ctx context.Context) *app {
	a := &app{cfg: c, store: s, ctx: ctx, invitation: randomID(), inviteEnd: time.Now().Add(10 * time.Minute), sessions: make(map[string]uploadSession), now: time.Now, downloadSlots: make(chan struct{}, c.Concurrency)}
	if c.ShareInbox {
		a.viewInvitation = randomID()
	}
	if c.AllowDownloads {
		a.downloadInvitation = randomID()
	}
	return a
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message}); err != nil {
		slog.Warn("could not deliver error response", "error", err)
	}
}

func (a *app) handler() http.Handler {
	mux := http.NewServeMux()
	for route, path := range map[string]string{
		"GET /{$}":                        "ui/index.html",
		"GET /style.css":                  "ui/style.css",
		"GET /app.js":                     "ui/dist/app.js",
		"GET /fonts/jetbrains-mono.woff2": "ui/fonts/jetbrains-mono.woff2",
		"GET /fonts/OFL.txt":              "ui/fonts/OFL.txt",
	} {
		data, err := assets.ReadFile(path)
		if err != nil {
			panic(err)
		}
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			switch filepath.Ext(path) {
			case ".html":
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
			case ".css":
				w.Header().Set("Content-Type", "text/css; charset=utf-8")
			case ".woff2":
				w.Header().Set("Content-Type", "font/woff2")
			case ".txt":
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			default:
				w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			}
			if _, err := w.Write(data); err != nil {
				slog.Warn("could not deliver frontend asset", "error", err)
			}
		})
	}
	mux.HandleFunc("POST /api/session", a.session)
	mux.HandleFunc("POST /api/uploads", a.upload)
	mux.HandleFunc("GET /api/inbox", a.inbox)
	mux.HandleFunc("GET /api/downloads/{id}", a.download)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		if "http://"+r.Host != a.cfg.PublicURL && "https://"+r.Host != a.cfg.PublicURL {
			writeError(w, http.StatusForbidden, "host", "Unexpected server address.")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("Origin") != a.cfg.PublicURL || r.Header.Get("X-Filedrop-Request") != "1" {
				writeError(w, http.StatusForbidden, "origin", "Request must come from this upload page.")
				return
			}
		}
		if r.URL.Path == "/api/inbox" {
			origin, site := r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site")
			if r.Header.Get("X-Filedrop-Request") != "1" || (origin != "" && origin != a.cfg.PublicURL) || (site != "" && site != "same-origin") {
				writeError(w, 403, "origin", "Inbox requests must come from this page.")
				return
			}
		}
		if strings.HasPrefix(r.URL.Path, "/api/downloads/") {
			origin, site := r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site")
			if (origin != "" && origin != a.cfg.PublicURL) || (site != "" && site != "same-origin" && site != "none") {
				writeError(w, 403, "origin", "Downloads must originate from this page.")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *app) session(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		slog.Error("cannot enforce session read deadline", "error", err)
		writeError(w, 500, "deadline", "Cannot safely authorize uploads.")
		return
	}
	defer func() {
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			slog.Warn("cannot reset session read deadline", "error", err)
		}
	}()
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	var request struct {
		Invitation string `json:"invitation"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, 400, "request", "Invalid invitation request.")
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "request", "Only one invitation request is allowed.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for token, session := range a.sessions {
		if !now.Before(session.expiresAt) {
			delete(a.sessions, token)
		}
	}
	canDownload := a.cfg.AllowDownloads && subtle.ConstantTimeCompare([]byte(request.Invitation), []byte(a.downloadInvitation)) == 1
	viewInbox := canDownload || (a.cfg.ShareInbox && subtle.ConstantTimeCompare([]byte(request.Invitation), []byte(a.viewInvitation)) == 1)
	canUpload := subtle.ConstantTimeCompare([]byte(request.Invitation), []byte(a.invitation)) == 1
	if a.ctx.Err() != nil || !now.Before(a.inviteEnd) || (!canUpload && !viewInbox) {
		writeError(w, 401, "invitation", "Invitation is invalid or expired. Ask the receiver for a new link.")
		return
	}
	if len(a.sessions) >= 32 {
		writeError(w, 429, "sessions", "Session limit reached. Wait for existing sessions to expire.")
		return
	}
	if old, err := r.Cookie(cookieName); err == nil {
		delete(a.sessions, old.Value)
	}
	token := randomID()
	end := now.Add(30 * time.Minute)
	a.sessions[token] = uploadSession{expiresAt: end, viewInbox: viewInbox, canDownload: canDownload, offerKey: randomID()}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: !a.cfg.DevHTTP, SameSite: http.SameSiteStrictMode, MaxAge: 1800})
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"expires_at": end, "max_file_bytes": a.cfg.FileLimit, "can_view_inbox": viewInbox, "can_download": canDownload}); err != nil {
		slog.Warn("could not deliver session response", "error", err)
	}
}

func (a *app) authorized(r *http.Request) bool {
	_, ok := a.sessionAccess(r)
	return ok
}

func (a *app) sessionAccess(r *http.Request) (uploadSession, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || a.ctx.Err() != nil {
		return uploadSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	session, ok := a.sessions[cookie.Value]
	return session, ok && a.now().Before(session.expiresAt)
}

func (a *app) inbox(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionAccess(r)
	if !ok {
		writeError(w, 401, "session", "Session expired. Open a fresh invitation.")
		return
	}
	if !a.cfg.ShareInbox || !session.viewInbox {
		writeError(w, 403, "permission", "This invitation does not grant shared inbox access.")
		return
	}
	files, err := a.store.listInbox(r.Context())
	if err != nil {
		if errors.Is(err, errInboxLimit) {
			writeError(w, 409, "inbox_limit", "Inbox has too many entries to list. Move files out on the receiving PC.")
		} else {
			slog.Error("could not list inbox", "error", err)
			writeError(w, 500, "storage", "Could not read the inbox on the receiving PC.")
		}
		return
	}
	session, ok = a.sessionAccess(r)
	if !ok || !session.viewInbox {
		writeError(w, 401, "session", "Session expired before the inbox was read.")
		return
	}
	if session.canDownload {
		for i := range files {
			files[i].ID, err = signOffer(session.offerKey, files[i])
			if err != nil {
				slog.Error("could not authorize download offer", "error", err)
				writeError(w, 500, "offer", "Could not prepare downloads.")
				return
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"files": files}); err != nil {
		slog.Warn("could not deliver inbox listing", "error", err)
	}
}

func (a *app) storageError(w http.ResponseWriter, err error) {
	if errors.Is(err, errCapacity) {
		writeError(w, 507, "capacity", "Receiving storage or upload capacity is exhausted.")
	} else {
		slog.Error("upload storage failure", "error", err)
		writeError(w, 500, "storage", "Could not save the file on the receiving PC.")
	}
}

func (a *app) upload(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		writeError(w, 401, "session", "Upload session expired. Open a fresh invitation.")
		return
	}
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(a.cfg.UploadTimeout)); err != nil {
		slog.Error("cannot enforce upload read deadline", "error", err)
		writeError(w, 500, "deadline", "Cannot safely receive uploads.")
		return
	}
	defer func() {
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			slog.Warn("cannot reset read deadline", "error", err)
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.UploadTimeout)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	unblock := context.AfterFunc(ctx, func() {
		if err := controller.SetReadDeadline(time.Now()); err != nil {
			slog.Warn("cannot interrupt upload read", "error", err)
		}
	})
	defer unblock()
	if err := a.store.reserve(); err != nil {
		a.storageError(w, err)
		return
	}
	var committed int64
	defer func() { a.store.release(committed) }()
	r.Body = http.MaxBytesReader(w, r.Body, a.cfg.FileLimit+overheadLimit)
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" || len(params["boundary"]) > 70 {
		writeError(w, 400, "multipart", "Use one multipart file per upload.")
		return
	}
	counter := &countingReader{reader: r.Body, header: true}
	reader := multipart.NewReader(counter, params["boundary"])
	part, err := reader.NextRawPart()
	if err != nil {
		writeError(w, 400, "multipart", "Missing or oversized file headers.")
		return
	}
	counter.header = false
	disposition, fields, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	name := fields["filename"]
	if err != nil || disposition != "form-data" || fields["name"] != "file" || !safeName(name) || part.Header.Get("Content-Transfer-Encoding") != "" {
		writeError(w, 400, "filename", "Choose a file with a safe, non-hidden filename.")
		return
	}
	stage := filepath.Join(".filedrop-staging", "upload-"+randomID())
	file, err := a.store.root.OpenFile(stage, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		a.storageError(w, err)
		return
	}
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); err != nil {
				slog.Error("close interrupted upload", "error", err)
			}
		}
		if err := a.store.root.Remove(stage); err != nil {
			slog.Error("cleanup upload staging file", "error", err)
		}
	}()
	buffer := make([]byte, 64<<10)
	var size int64
	for {
		if ctx.Err() != nil {
			writeError(w, 408, "canceled", "Upload was interrupted or timed out.")
			return
		}
		n, readErr := part.Read(buffer)
		if n > 0 {
			if size+int64(n) > a.cfg.FileLimit {
				writeError(w, 413, "size", "File exceeds the receiving size limit.")
				return
			}
			if err := a.store.spaceOK(file, int64(n)); err != nil {
				a.storageError(w, err)
				return
			}
			written, err := file.Write(buffer[:n])
			if err != nil || written != n {
				if err == nil {
					err = io.ErrShortWrite
				}
				a.storageError(w, err)
				return
			}
			size += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(readErr, &tooLarge) {
				writeError(w, 413, "size", "Upload exceeds the receiving size limit.")
			} else {
				writeError(w, 400, "interrupted", "Upload data was incomplete or malformed.")
			}
			return
		}
	}
	counter.header = true
	if _, err := reader.NextRawPart(); err != io.EOF {
		writeError(w, 400, "multipart", "Exactly one file is allowed per request.")
		return
	}
	if _, err := io.Copy(io.Discard, counter); err != nil || counter.total-size > overheadLimit {
		writeError(w, 400, "multipart", "Upload has excessive or invalid multipart overhead.")
		return
	}
	if ctx.Err() != nil || !a.authorized(r) {
		writeError(w, 401, "session", "Authorization expired before the file was saved.")
		return
	}
	if err := quarantine(file); err != nil {
		a.storageError(w, fmt.Errorf("apply quarantine: %w", err))
		return
	}
	if err := file.Sync(); err != nil {
		a.storageError(w, err)
		return
	}
	err = file.Close()
	closed = true
	if err != nil {
		a.storageError(w, err)
		return
	}
	// Recheck after potentially slow storage operations before publication.
	if ctx.Err() != nil || !a.authorized(r) {
		writeError(w, 401, "session", "Authorization expired before the file was saved.")
		return
	}
	storedName, err := a.store.finalize(stage, name)
	if err != nil {
		a.storageError(w, err)
		return
	}
	committed = size
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(map[string]any{"name": storedName, "bytes": size}); err != nil {
		slog.Warn("file saved but completion response could not be delivered", "error", err)
	}
}

type countingReader struct {
	reader             io.Reader
	total, headerBytes int64
	header             bool
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.header {
		remaining := overheadLimit - c.headerBytes
		if remaining <= 0 {
			return 0, errors.New("multipart overhead limit exceeded")
		}
		if int64(len(p)) > remaining {
			p = p[:remaining]
		}
	}
	n, err := c.reader.Read(p)
	c.total += int64(n)
	if c.header {
		c.headerBytes += int64(n)
	}
	return n, err
}
