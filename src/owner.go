package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/yeqown/go-qrcode/v2"
)

type invitation struct {
	token       string
	expiresAt   time.Time
	viewInbox   bool
	canDownload bool
}

func (a *app) ownerOrigin() string {
	return "http://" + a.cfg.OwnerListen
}

func (a *app) ownerHandler() http.Handler {
	mux := http.NewServeMux()
	for route, path := range map[string]string{
		"GET /{$}":                        "ui/owner.html",
		"GET /owner.js":                   "ui/dist/owner.js",
		"GET /style.css":                  "ui/style.css",
		"GET /fonts/jetbrains-mono.woff2": "ui/fonts/jetbrains-mono.woff2",
	} {
		mux.HandleFunc(route, assetHandler(path))
	}
	mux.HandleFunc("POST /api/owner/session", a.ownerSession)
	mux.HandleFunc("GET /api/owner/status", a.ownerStatus)
	mux.HandleFunc("POST /api/owner/invitations", a.ownerInvitation)
	mux.HandleFunc("POST /api/owner/qr", a.ownerQR)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !net.ParseIP(host).IsLoopback() || r.Host != a.cfg.OwnerListen || a.cfg.OwnerListen == "" {
			writeError(w, 403, "owner_host", "Owner access is restricted to the local receiver.")
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/owner/") {
			origin, site := r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site")
			if r.Header.Get("X-Filedrop-Request") != "1" || (origin != "" && origin != a.ownerOrigin()) || (site != "" && site != "same-origin") || (r.Method != http.MethodGet && r.Method != http.MethodHead && origin != a.ownerOrigin()) {
				writeError(w, 403, "origin", "Owner requests must come from the local owner page.")
				return
			}
			if r.URL.Path != "/api/owner/session" && !a.ownerAuthorized(r) {
				writeError(w, 401, "owner_session", "Open the owner link printed on the receiving computer.")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *app) ownerAuthorized(r *http.Request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ctx.Err() == nil && a.ownerCredential != "" && a.now().Before(a.ownerEnd) &&
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+a.ownerCredential)) == 1
}

func decodeOwnerRequest(w http.ResponseWriter, r *http.Request, target any) bool {
	controller := http.NewResponseController(w)
	if err := controller.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		slog.Error("cannot enforce owner request deadline", "error", err)
		writeError(w, 500, "deadline", "Cannot safely process this owner request.")
		return false
	}
	defer func() {
		if err := controller.SetReadDeadline(time.Time{}); err != nil {
			slog.Warn("cannot reset owner request deadline", "error", err)
		}
	}()
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, 400, "request", "Invalid owner request.")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		writeError(w, 400, "request", "Only one owner request is allowed.")
		return false
	}
	return true
}

func ownerJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("could not deliver owner response", "error", err)
	}
}

func (a *app) ownerSession(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Bootstrap string `json:"bootstrap"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx.Err() != nil || a.ownerBootstrap == "" || !a.now().Before(a.ownerBootstrapEnd) || subtle.ConstantTimeCompare([]byte(request.Bootstrap), []byte(a.ownerBootstrap)) != 1 {
		writeError(w, 401, "bootstrap", "Owner link is invalid, expired or already used.")
		return
	}
	a.ownerBootstrap = ""
	a.ownerCredential = randomID()
	a.ownerEnd = a.now().Add(8 * time.Hour)
	ownerJSON(w, map[string]any{"credential": a.ownerCredential, "expires_at": a.ownerEnd})
}

func (a *app) ownerStatus(w http.ResponseWriter, r *http.Request) {
	ownerJSON(w, map[string]any{"can_view_inbox": a.cfg.ShareInbox, "can_download": a.cfg.AllowDownloads})
}

func (a *app) ownerInvitation(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Permission string `json:"permission"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	if request.Permission != "upload" && request.Permission != "view" && request.Permission != "download" {
		writeError(w, 400, "permission", "Choose upload, view or download.")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ctx.Err() != nil || !a.now().Before(a.ownerEnd) {
		writeError(w, 401, "owner_session", "Owner session ended.")
		return
	}
	if (request.Permission == "view" && !a.cfg.ShareInbox) || (request.Permission == "download" && !a.cfg.AllowDownloads) {
		writeError(w, 403, "permission", "This permission is disabled on the receiver.")
		return
	}
	invite := invitation{
		token: randomID(), expiresAt: a.now().Add(10 * time.Minute),
		viewInbox: request.Permission != "upload", canDownload: request.Permission == "download",
	}
	// Replace only this permission's invitation; existing guest sessions keep their scope.
	a.invitations[request.Permission] = invite
	ownerJSON(w, map[string]any{"url": a.cfg.PublicURL + "/#" + invite.token, "permission": request.Permission, "expires_at": invite.expiresAt})
}

func (a *app) ownerQR(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Permission string `json:"permission"`
		Invitation string `json:"invitation"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	a.mu.Lock()
	invite, ok := a.invitations[request.Permission]
	now := a.now()
	a.mu.Unlock()
	if !ok || !now.Before(invite.expiresAt) || subtle.ConstantTimeCompare([]byte(request.Invitation), []byte(invite.token)) != 1 {
		writeError(w, 410, "invitation", "Invitation expired. Create a new link.")
		return
	}
	code, err := qrcode.New(a.cfg.PublicURL + "/#" + invite.token)
	if err != nil {
		slog.Error("could not encode invitation QR", "error", err)
		writeError(w, 500, "qr", "Could not create the QR code.")
		return
	}
	writer := &qrPNG{}
	if err := code.Save(writer); err != nil {
		slog.Error("could not render invitation QR", "error", err)
		writeError(w, 500, "qr", "Could not render the QR code.")
		return
	}
	if !a.ownerAuthorized(r) {
		writeError(w, 401, "owner_session", "Owner session ended.")
		return
	}
	a.mu.Lock()
	current := a.invitations[request.Permission]
	valid := a.now().Before(current.expiresAt) && current.token == invite.token
	a.mu.Unlock()
	if !valid {
		writeError(w, 410, "invitation", "Invitation changed. Create a new link.")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	if _, err := w.Write(writer.Bytes()); err != nil {
		slog.Warn("could not deliver QR code", "error", err)
	}
}

type qrPNG struct{ bytes.Buffer }

func (w *qrPNG) Close() error { return nil }

func (w *qrPNG) Write(matrix qrcode.Matrix) error {
	const scale, quiet = 6, 4
	bitmap := matrix.Bitmap()
	if matrix.Width() <= 0 || matrix.Width() != matrix.Height() {
		return errors.New("invalid QR matrix")
	}
	size := (matrix.Width() + quiet*2) * scale
	img := image.NewGray(image.Rect(0, 0, size, size))
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			col, row := x/scale-quiet, y/scale-quiet
			value := uint8(255)
			if col >= 0 && row >= 0 && col < matrix.Width() && row < matrix.Height() && bitmap[col][row] {
				value = 0
			}
			img.SetGray(x, y, color.Gray{Y: value})
		}
	}
	return png.Encode(&w.Buffer, img)
}
