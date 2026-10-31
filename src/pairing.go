package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type proofPayload struct {
	Version     int    `json:"version"`
	Nonce       string `json:"nonce"`
	Receiver    string `json:"receiver"`
	Epoch       string `json:"epoch"`
	Origin      string `json:"origin"`
	Fingerprint string `json:"fingerprint"`
	Purpose     string `json:"purpose"`
	ClientID    string `json:"client_id"`
	Context     string `json:"context"`
	Expires     int64  `json:"expires"`
}

type pairingChallenge struct {
	payload     proofPayload
	bytes       []byte
	public      *ecdsa.PublicKey
	spki        string
	inviteKey   string
	inviteToken string
	grant       string
	name        string
	generation  int64
}

type pendingTicket struct {
	id      string
	expires int64
}

func parsePublicKey(encoded string) (*ecdsa.PublicKey, string, error) {
	if len(encoded) > 512 {
		return nil, "", errPairingAuth
	}
	der, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return nil, "", errPairingAuth
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, "", errPairingAuth
	}
	public, ok := key.(*ecdsa.PublicKey)
	if !ok || public.Curve != elliptic.P256() || !public.Curve.IsOnCurve(public.X, public.Y) {
		return nil, "", errPairingAuth
	}
	canonical, err := x509.MarshalPKIXPublicKey(public)
	if err != nil || base64.StdEncoding.EncodeToString(canonical) != encoded {
		return nil, "", errPairingAuth
	}
	sum := sha256.Sum256(canonical)
	return public, hex.EncodeToString(sum[:16]), nil
}

func (a *app) registryFailureLocked(err error) {
	if a.pairingFault.CompareAndSwap(false, true) {
		slog.Error("pairing registry unavailable; authorization stopped until restart", "error", err)
		for id, stop := range a.pairedStops {
			close(stop)
			delete(a.pairedStops, id)
		}
	}
}

func (a *app) authError(w http.ResponseWriter, message string) {
	if a.pairingFault.Load() {
		writeError(w, 503, "registry", "Pairing state is unavailable. Receiver restart and inspection are required.")
		return
	}
	writeError(w, 401, "session", message)
}

func (a *app) pairingInfo(w http.ResponseWriter, r *http.Request) {
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil {
		ownerJSON(w, map[string]any{"enabled": false})
		return
	}
	if a.pairingFault.Load() {
		a.authError(w, "")
		return
	}
	ownerJSON(w, map[string]any{"enabled": true, "receiver": a.registry.receiver, "epoch": a.registry.epoch, "origin": a.cfg.PublicURL})
}

func (a *app) pairingChallenge(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Purpose    string `json:"purpose"`
		Invitation string `json:"invitation"`
		PublicKey  string `json:"public_key"`
		ClientID   string `json:"client_id"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() || a.ctx.Err() != nil {
		a.authError(w, "Pairing is unavailable.")
		return
	}
	now := a.now()
	if now.Sub(a.challengeWindow) >= time.Minute {
		a.challengeWindow = now
		a.challengeCount = 0
	}
	a.challengeCount++
	if a.challengeCount > 120 {
		writeError(w, 429, "rate", "Too many pairing requests. Try again in a minute.")
		return
	}
	for id, ch := range a.challenges {
		if ch.payload.Expires <= now.UnixMilli() {
			delete(a.challenges, id)
		}
	}
	if len(a.challenges) >= 64 {
		writeError(w, 429, "capacity", "Pairing challenge capacity reached.")
		return
	}
	ch := pairingChallenge{}
	var err error
	if request.Purpose == "enroll" {
		ch.public, ch.payload.Fingerprint, err = parsePublicKey(request.PublicKey)
		if err != nil {
			a.authError(w, "Pairing authentication failed.")
			return
		}
		a.mu.Lock()
		for key, invite := range a.invitations {
			if invite.pair && invite.token == request.Invitation && now.Before(invite.expiresAt) {
				ch.inviteKey = key
				ch.inviteToken = invite.token
				ch.grant = strings.TrimPrefix(key, "pair-")
				ch.name = invite.name
			}
		}
		a.mu.Unlock()
		if ch.inviteKey == "" {
			a.authError(w, "Pairing authentication failed.")
			return
		}
		ch.spki = request.PublicKey
		ch.payload.ClientID = randomID()
		contextHash := sha256.Sum256([]byte(request.Invitation))
		ch.payload.Context = hex.EncodeToString(contextHash[:])
	} else if request.Purpose == "login" && validID(request.ClientID) {
		client, err := a.registry.client(request.ClientID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				a.registryFailureLocked(err)
			}
			a.authError(w, "Pairing authentication failed.")
			return
		}
		if client.Status != "active" {
			a.authError(w, "Pairing authentication failed.")
			return
		}
		ch.public, ch.payload.Fingerprint, err = parsePublicKey(client.PublicKey)
		if err != nil {
			a.registryFailureLocked(errors.New("invalid registered key"))
			a.authError(w, "")
			return
		}
		ch.spki = client.PublicKey
		ch.payload.ClientID = client.ID
		ch.generation = client.Generation
		ch.grant = client.Permission
		ch.payload.Context = client.ID
	} else {
		writeError(w, 400, "purpose", "Choose enrollment or login.")
		return
	}
	ch.payload.Version = 1
	ch.payload.Nonce = randomID()
	ch.payload.Receiver = a.registry.receiver
	ch.payload.Epoch = a.registry.epoch
	ch.payload.Origin = a.cfg.PublicURL
	ch.payload.Purpose = request.Purpose
	ch.payload.Expires = now.Add(time.Minute).UnixMilli()
	ch.bytes, err = json.Marshal(ch.payload)
	if err != nil {
		writeError(w, 500, "challenge", "Could not encode pairing challenge.")
		return
	}
	id := randomID()
	a.challenges[id] = ch
	ownerJSON(w, map[string]any{"id": id, "payload": base64.StdEncoding.EncodeToString(ch.bytes)})
}

func (a *app) pairingProof(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID        string `json:"id"`
		Signature string `json:"signature"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() || a.ctx.Err() != nil {
		a.authError(w, "Pairing unavailable.")
		return
	}
	ch, ok := a.challenges[request.ID]
	delete(a.challenges, request.ID)
	signature, err := base64.StdEncoding.Strict().DecodeString(request.Signature)
	if !ok || err != nil || len(signature) != 64 || ch.payload.Expires <= a.now().UnixMilli() {
		a.authError(w, "Pairing authentication failed.")
		return
	}
	sum := sha256.Sum256(ch.bytes)
	if !ecdsa.Verify(ch.public, sum[:], new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])) {
		a.authError(w, "Pairing authentication failed.")
		return
	}
	if ch.payload.Purpose == "enroll" {
		a.mu.Lock()
		invite := a.invitations[ch.inviteKey]
		valid := invite.token == ch.inviteToken && a.now().Before(invite.expiresAt)
		a.mu.Unlock()
		if !valid {
			a.authError(w, "Enrollment invitation was consumed or expired.")
			return
		}
		p, err := a.registry.addApproval(approval{ClientID: ch.payload.ClientID, Name: ch.name, PublicKey: ch.spki, Fingerprint: ch.payload.Fingerprint, Permission: ch.grant, Operation: "enroll", Expires: invite.expiresAt.UnixMilli()}, a.now())
		if err != nil {
			a.pairingDBError(w, err)
			return
		}
		a.mu.Lock()
		delete(a.invitations, ch.inviteKey)
		a.mu.Unlock()
		for token, ticket := range a.pendingTickets {
			if ticket.expires <= a.now().UnixMilli() {
				delete(a.pendingTickets, token)
			}
		}
		ticket := randomID()
		a.pendingTickets[ticket] = pendingTicket{id: p.ID, expires: p.Expires}
		ownerJSON(w, map[string]any{"pending_id": p.ID, "pending_token": ticket, "client_id": p.ClientID, "fingerprint": p.Fingerprint, "expires": p.Expires})
		return
	}
	client, err := a.registry.client(ch.payload.ClientID)
	if err != nil {
		a.pairingDBError(w, err)
		return
	}
	if client.Status != "active" || client.Generation != ch.generation || client.PublicKey != ch.spki {
		a.authError(w, "Pairing authentication failed.")
		return
	}
	if _, err := a.registry.db.Exec("UPDATE clients SET last_seen=? WHERE id=?", a.now().UnixMilli(), client.ID); err != nil {
		a.pairingDBError(w, err)
		return
	}
	if _, ok := a.pairedStops[client.ID]; !ok {
		a.pairedStops[client.ID] = make(chan struct{})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for token, session := range a.sessions {
		if !a.now().Before(session.expiresAt) {
			delete(a.sessions, token)
		}
	}
	if old, err := r.Cookie(cookieName); err == nil {
		delete(a.sessions, old.Value)
	}
	if len(a.sessions) >= 32 {
		writeError(w, 429, "sessions", "Session limit reached.")
		return
	}
	session := uploadSession{expiresAt: a.now().Add(30 * time.Minute), canUpload: true, viewInbox: permissionRank(client.Permission) >= 2, canDownload: permissionRank(client.Permission) >= 3, offerKey: randomID(), clientID: client.ID, generation: client.Generation, epoch: a.registry.epoch, stop: a.pairedStops[client.ID]}
	token := randomID()
	a.sessions[token] = session
	a.respondSession(w, token, session)
}

func (a *app) pairingDBError(w http.ResponseWriter, err error) {
	if errors.Is(err, errCapacity) {
		writeError(w, 429, "capacity", "Pairing capacity reached.")
		return
	}
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, errStaleApproval) {
		writeError(w, 409, "stale", "Pairing state changed. Refresh and try again.")
		return
	}
	a.registryFailureLocked(err)
	a.authError(w, "")
}

func (a *app) pendingStatus(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() {
		a.authError(w, "Pairing unavailable.")
		return
	}
	ticket, ok := a.pendingTickets[request.Token]
	if !ok || ticket.id != request.ID || ticket.expires <= a.now().UnixMilli() {
		delete(a.pendingTickets, request.Token)
		a.authError(w, "Pairing request expired.")
		return
	}
	p, err := a.registry.pending(request.ID)
	if err != nil {
		a.pairingDBError(w, err)
		return
	}
	ownerJSON(w, map[string]any{"status": p.Status, "client_id": p.ClientID})
}

func (a *app) respondSession(w http.ResponseWriter, token string, session uploadSession) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: !a.cfg.DevHTTP, SameSite: http.SameSiteStrictMode, MaxAge: 1800})
	ownerJSON(w, map[string]any{"expires_at": session.expiresAt, "max_file_bytes": a.cfg.FileLimit, "can_view_inbox": session.viewInbox, "can_download": session.canDownload, "can_upload": session.canUpload})
}

func (a *app) currentSessionLocked(r *http.Request) (uploadSession, bool) {
	cookie, err := r.Cookie(cookieName)
	if err != nil || a.ctx.Err() != nil || a.pairingFault.Load() {
		return uploadSession{}, false
	}
	a.mu.Lock()
	session, ok := a.sessions[cookie.Value]
	a.mu.Unlock()
	if !ok || !a.now().Before(session.expiresAt) {
		return session, false
	}
	if session.clientID != "" {
		if a.registry == nil {
			return session, false
		}
		client, err := a.registry.client(session.clientID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				a.registryFailureLocked(err)
			}
			return session, false
		}
		if client.Status != "active" || client.Generation != session.generation || session.epoch != a.registry.epoch {
			return session, false
		}
		rank := permissionRank(client.Permission)
		session.canUpload = rank >= 1
		session.viewInbox = session.viewInbox && rank >= 2 && a.cfg.ShareInbox
		session.canDownload = session.canDownload && rank >= 3 && a.cfg.AllowDownloads
	}
	return session, true
}

func watchRevocation(ctx context.Context, stop <-chan struct{}, cancel context.CancelFunc) func() {
	done := make(chan struct{})
	if stop != nil {
		go func() {
			select {
			case <-stop:
				cancel()
			case <-ctx.Done():
			case <-done:
			}
		}()
	}
	return func() { close(done) }
}

func (a *app) publishUpload(ctx context.Context, r *http.Request, stage, name string) (string, error) {
	a.authority.Lock()
	defer a.authority.Unlock()
	session, ok := a.currentSessionLocked(r)
	if ctx.Err() != nil || !ok || !session.canUpload {
		return "", errPairingAuth
	}
	return a.store.finalize(stage, name)
}

func (a *app) invalidateClientLocked(id string) {
	if stop, ok := a.pairedStops[id]; ok {
		close(stop)
		delete(a.pairedStops, id)
	}
	a.mu.Lock()
	for token, session := range a.sessions {
		if session.clientID == id {
			delete(a.sessions, token)
		}
	}
	a.mu.Unlock()
	for nonce, ch := range a.challenges {
		if ch.payload.ClientID == id {
			delete(a.challenges, nonce)
		}
	}
}
