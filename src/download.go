package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var errOfferChanged = errors.New("offered file changed or was removed")
var errDownloadCanceled = errors.New("download authorization ended")

type fileIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
}

type downloadOffer struct {
	Name         string       `json:"name"`
	Bytes        int64        `json:"bytes"`
	ModifiedNano int64        `json:"modified"`
	Identity     fileIdentity `json:"identity"`
}

func signOffer(key string, file inboxFile) (string, error) {
	payload, err := json.Marshal(downloadOffer{Name: file.Name, Bytes: file.Bytes, ModifiedNano: file.ModifiedAt.UnixNano(), Identity: file.identity})
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func verifyOffer(key, id string) (downloadOffer, error) {
	var offer downloadOffer
	if len(id) > 1024 {
		return offer, errors.New("invalid offer")
	}
	parts := strings.Split(id, ".")
	if len(parts) != 2 {
		return offer, errors.New("invalid offer")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return offer, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return offer, err
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(payload)
	if !hmac.Equal(signature, mac.Sum(nil)) {
		return offer, errors.New("invalid offer signature")
	}
	if err := json.Unmarshal(payload, &offer); err != nil {
		return offer, err
	}
	if !safeName(offer.Name) || offer.Bytes < 0 {
		return offer, errors.New("invalid offer file")
	}
	return offer, nil
}

func (a *app) download(w http.ResponseWriter, r *http.Request) {
	session, ok := a.sessionAccess(r)
	if !ok {
		writeError(w, 401, "session", "Session expired. Open a fresh invitation.")
		return
	}
	if !a.cfg.AllowDownloads || !session.canDownload {
		writeError(w, 403, "permission", "This invitation does not allow downloads.")
		return
	}
	offer, err := verifyOffer(session.offerKey, r.PathValue("id"))
	if err != nil {
		writeError(w, 403, "offer", "Invalid download offer. Refresh the inbox.")
		return
	}
	if r.Header.Get("Range") != "" {
		writeError(w, 416, "range", "Resuming downloads is not supported.")
		return
	}
	select {
	case a.downloadSlots <- struct{}{}:
		defer func() { <-a.downloadSlots }()
	default:
		writeError(w, 429, "capacity", "Too many downloads. Try again shortly.")
		return
	}
	file, err := a.store.openDownload(offer)
	if err != nil {
		if errors.Is(err, errOfferChanged) {
			writeError(w, 409, "changed", "File changed or was removed. Refresh the inbox.")
		} else {
			slog.Error("could not open download", "error", err)
			writeError(w, 500, "storage", "Could not open this file.")
		}
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			slog.Error("close download", "error", err)
		}
	}()
	controller := http.NewResponseController(w)
	if err := controller.SetWriteDeadline(time.Now().Add(a.cfg.UploadTimeout)); err != nil {
		slog.Error("cannot enforce download deadline", "error", err)
		writeError(w, 500, "deadline", "Cannot safely send this file.")
		return
	}
	defer func() {
		if err := controller.SetWriteDeadline(time.Time{}); err != nil {
			slog.Warn("cannot reset download deadline", "error", err)
		}
	}()
	ctx, cancel := context.WithTimeout(r.Context(), a.cfg.UploadTimeout)
	defer cancel()
	stop := context.AfterFunc(a.ctx, cancel)
	defer stop()
	unblock := context.AfterFunc(ctx, func() {
		if err := controller.SetWriteDeadline(time.Now()); err != nil {
			slog.Warn("cannot interrupt download", "error", err)
		}
	})
	defer unblock()
	if session, ok := a.sessionAccess(r); ctx.Err() != nil || !ok || !session.canDownload {
		writeError(w, 401, "session", "Download session ended.")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": offer.Name}))
	w.Header().Set("Content-Length", strconv.FormatInt(offer.Bytes, 10))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	writer := downloadWriter{app: a, request: r, ctx: ctx, writer: w}
	n, err := io.CopyBuffer(writer, io.LimitReader(file, offer.Bytes), make([]byte, 64<<10))
	if err == nil && n != offer.Bytes {
		err = io.ErrUnexpectedEOF
	}
	if err != nil {
		slog.Warn("download interrupted; browser must not treat it as complete", "bytes_sent", n, "error", err)
	}
}

type downloadWriter struct {
	app     *app
	request *http.Request
	ctx     context.Context
	writer  io.Writer
}

func (w downloadWriter) Write(data []byte) (int, error) {
	session, ok := w.app.sessionAccess(w.request)
	if w.ctx.Err() != nil || !ok || !session.canDownload {
		return 0, errDownloadCanceled
	}
	return w.writer.Write(data)
}
