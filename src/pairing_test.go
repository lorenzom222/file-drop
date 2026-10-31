package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type proofResult struct {
	PendingID    string `json:"pending_id"`
	PendingToken string `json:"pending_token"`
	ClientID     string `json:"client_id"`
}
type challengeResult struct {
	ID      string `json:"id"`
	Payload string `json:"payload"`
}

func setupPairing(t *testing.T) (*ownerFixture, string) {
	t.Helper()
	o := setupOwner(t, true, true)
	state, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	o.f.app.cfg.StateDir = state
	r, err := openRegistry(state, true)
	if err != nil {
		t.Fatal(err)
	}
	o.f.app.registry = r
	t.Cleanup(func() {
		if err := r.close(); err != nil {
			t.Error(err)
		}
	})
	return o, state
}
func browserKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, base64.StdEncoding.EncodeToString(der)
}
func pairingRequest(t *testing.T, f *fixture, path string, input any) *http.Response {
	t.Helper()
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return f.request(t, path, bytes.NewReader(data), "application/json", nil)
}
func challenge(t *testing.T, f *fixture, input any) challengeResult {
	t.Helper()
	res := pairingRequest(t, f, "/api/pairing/challenge", input)
	defer res.Body.Close()
	var result challengeResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 {
		t.Fatalf("challenge: %d", res.StatusCode)
	}
	return result
}
func signature(t *testing.T, key *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, 64)
	r.FillBytes(encoded[:32])
	s.FillBytes(encoded[32:])
	return base64.StdEncoding.EncodeToString(encoded)
}
func proof(t *testing.T, f *fixture, key *ecdsa.PrivateKey, ch challengeResult) *http.Response {
	t.Helper()
	return pairingRequest(t, f, "/api/pairing/proof", map[string]string{"id": ch.ID, "signature": signature(t, key, ch.Payload)})
}
func enrollment(t *testing.T, o *ownerFixture, grant string) (*ecdsa.PrivateKey, proofResult) {
	t.Helper()
	key, spki := browserKey(t)
	res := o.request(t, "/api/owner/invitations", map[string]string{"mode": "remember", "name": "Test browser", "permission": grant}, o.credential)
	var link struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(res.Body).Decode(&link); err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("enrollment invite: %d", res.StatusCode)
	}
	token := link.URL[len(o.f.app.cfg.PublicURL+"/#pair="):]
	ch := challenge(t, o.f, map[string]string{"purpose": "enroll", "invitation": token, "public_key": spki})
	res = proof(t, o.f, key, ch)
	defer res.Body.Close()
	var result proofResult
	if err := json.NewDecoder(res.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if res.StatusCode != 200 || !validID(result.PendingID) {
		t.Fatalf("enrollment proof: %d %#v", res.StatusCode, result)
	}
	return key, result
}
func approve(t *testing.T, o *ownerFixture, p proofResult) {
	t.Helper()
	a := o.f.app
	a.authority.Lock()
	pending, err := a.registry.pending(p.PendingID)
	a.authority.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.confirmApproval(pending.ID, pending.Digest); err != nil {
		t.Fatal(err)
	}
}
func login(t *testing.T, o *ownerFixture, key *ecdsa.PrivateKey, id string) *http.Cookie {
	t.Helper()
	ch := challenge(t, o.f, map[string]string{"purpose": "login", "client_id": id})
	res := proof(t, o.f, key, ch)
	defer res.Body.Close()
	if res.StatusCode != 200 || len(res.Cookies()) != 1 {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("login: %d %s", res.StatusCode, body)
	}
	return res.Cookies()[0]
}

func TestPersistentPairingLifecycle(t *testing.T) {
	o, _ := setupPairing(t)
	key, pending := enrollment(t, o, "download")
	res := pairingRequest(t, o.f, "/api/pairing/challenge", map[string]string{"purpose": "login", "client_id": pending.ClientID})
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("unapproved browser logged in")
	}
	approve(t, o, pending)
	cookie := login(t, o, key, pending.ClientID)
	body, ct := multipartBody(t, "paired.txt", []byte("paired bytes"), false)
	res = o.f.request(t, "/api/uploads", body, ct, cookie)
	res.Body.Close()
	if res.StatusCode != 201 {
		t.Fatal("paired upload failed")
	}
	files := readInbox(t, o.f, cookie)
	if len(files) != 1 || files[0].ID == "" {
		t.Fatal("paired offers missing")
	}
	res = getDownload(t, o.f, cookie, files[0].ID, "", "same-origin", "")
	data, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != 200 || string(data) != "paired bytes" {
		t.Fatal("paired download mismatch")
	}
	res = o.request(t, "/api/owner/clients", map[string]string{"id": pending.ClientID, "action": "edit", "name": "Reduced", "permission": "upload"}, o.credential)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("reduce failed")
	}
	res = getDownload(t, o.f, cookie, files[0].ID, "", "same-origin", "")
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("old offer/session survived reduction")
	}
	cookie = login(t, o, key, pending.ClientID)
	res = getInbox(t, o.f, cookie, "", "same-origin", "", "1")
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("reduced grant still listed inbox")
	}
	res = o.request(t, "/api/owner/clients", map[string]string{"id": pending.ClientID, "action": "revoke"}, o.credential)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("revoke failed")
	}
	res = pairingRequest(t, o.f, "/api/pairing/challenge", map[string]string{"purpose": "login", "client_id": pending.ClientID})
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("revoked identity can reconnect")
	}
}

func TestProofReplayAndSubstitution(t *testing.T) {
	o, _ := setupPairing(t)
	key, p := enrollment(t, o, "upload")
	approve(t, o, p)
	ch := challenge(t, o.f, map[string]string{"purpose": "login", "client_id": p.ClientID})
	wrong, _ := browserKey(t)
	res := proof(t, o.f, wrong, ch)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("key substitution accepted")
	}
	res = proof(t, o.f, key, ch)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("failed challenge could be replayed")
	}
	ch = challenge(t, o.f, map[string]string{"purpose": "login", "client_id": p.ClientID})
	o.f.clock.Add(int64(61 * time.Second))
	res = proof(t, o.f, key, ch)
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("expired challenge accepted")
	}
}

func TestStaleApprovalAndStateReset(t *testing.T) {
	o, _ := setupPairing(t)
	key, p := enrollment(t, o, "upload")
	approve(t, o, p)
	login(t, o, key, p.ClientID)
	res := o.request(t, "/api/owner/clients", map[string]string{"id": p.ClientID, "action": "edit", "name": "Increase", "permission": "download"}, o.credential)
	var increase struct {
		ID string `json:"request_id"`
	}
	json.NewDecoder(res.Body).Decode(&increase)
	res.Body.Close()
	a := o.f.app
	a.authority.Lock()
	pending, err := a.registry.pending(increase.ID)
	a.authority.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	res = o.request(t, "/api/owner/clients", map[string]string{"id": p.ClientID, "action": "revoke"}, o.credential)
	res.Body.Close()
	if _, err := a.confirmApproval(pending.ID, pending.Digest); !errors.Is(err, errStaleApproval) {
		t.Fatalf("stale increase: %v", err)
	}
	_, unapproved := enrollment(t, o, "upload")
	a.authority.Lock()
	pending, err = a.registry.pending(unapproved.PendingID)
	a.authority.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	reset := a.control(controlRequest{Operation: "reset-trust"})
	if reset.Error != "" {
		t.Fatal(reset.Error)
	}
	if _, err := a.confirmApproval(pending.ID, pending.Digest); !errors.Is(err, errStaleApproval) {
		t.Fatal("trust reset left pending approval usable")
	}
}

func TestRegistryFailClosedAndRestart(t *testing.T) {
	o, state := setupPairing(t)
	key, p := enrollment(t, o, "upload")
	approve(t, o, p)
	cookie := login(t, o, key, p.ClientID)
	o.f.app.authority.Lock()
	if err := o.f.app.registry.db.Close(); err != nil {
		t.Fatal(err)
	}
	o.f.app.authority.Unlock()
	body, ct := multipartBody(t, "should-not-save.txt", []byte("no"), false)
	res := o.f.request(t, "/api/uploads", body, ct, cookie)
	res.Body.Close()
	if res.StatusCode != 503 || !o.f.app.pairingFault.Load() {
		t.Fatal("database failure did not stop authorization")
	}
	assertEmptyStage(t, o.f)
	if err := o.f.app.registry.lock.Close(); err != nil {
		t.Fatal(err)
	}
	o.f.app.registry.lock = nil
	r, err := openRegistry(state, false)
	if err != nil {
		t.Fatal(err)
	}
	defer r.close()
	client, err := r.client(p.ClientID)
	if err != nil || client.Status != "active" {
		t.Fatal("persistent identity lost across reopen")
	}
	missing, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := openRegistry(missing, false); err == nil {
		r.close()
		t.Fatal("missing registry silently initialized")
	}
}

func TestPublicationRevocationOrdering(t *testing.T) {
	o, _ := setupPairing(t)
	key, p := enrollment(t, o, "upload")
	approve(t, o, p)
	cookie := login(t, o, key, p.ClientID)
	stage := ".filedrop-staging/upload-" + randomID()
	if err := os.WriteFile(filepath.Join(o.f.app.cfg.Inbox, stage), []byte("staged"), 0600); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("POST", o.f.server.URL, nil)
	req.AddCookie(cookie)
	res := o.request(t, "/api/owner/clients", map[string]string{"id": p.ClientID, "action": "revoke"}, o.credential)
	res.Body.Close()
	if _, err := o.f.app.publishUpload(context.Background(), req, stage, "not-published.txt"); !errors.Is(err, errPairingAuth) {
		t.Fatal("published after revocation")
	}
	if err := os.Remove(filepath.Join(o.f.app.cfg.Inbox, stage)); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentInvitationRedemption(t *testing.T) {
	o, _ := setupPairing(t)
	key, spki := browserKey(t)
	res := o.request(t, "/api/owner/invitations", map[string]string{"mode": "remember", "name": "Concurrent", "permission": "upload"}, o.credential)
	var link struct {
		URL string `json:"url"`
	}

	json.NewDecoder(res.Body).Decode(&link)
	res.Body.Close()
	token := link.URL[len(o.f.app.cfg.PublicURL+"/#pair="):]
	ch1 := challenge(t, o.f, map[string]string{"purpose": "enroll", "invitation": token, "public_key": spki})
	ch2 := challenge(t, o.f, map[string]string{"purpose": "enroll", "invitation": token, "public_key": spki})
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, ch := range []challengeResult{ch1, ch2} {
		wg.Add(1)
		go func(ch challengeResult) {
			defer wg.Done()
			res := proof(t, o.f, key, ch)
			statuses <- res.StatusCode
			res.Body.Close()
		}(ch)
	}
	wg.Wait()
	close(statuses)
	success := 0
	for status := range statuses {
		if status == 200 {
			success++
		} else if status != 401 {
			t.Fatalf("redemption status: %d", status)
		}
	}
	if success != 1 {
		t.Fatal("invitation was not single-use")
	}
}

func TestConfirmationReplayAndTransferCancellation(t *testing.T) {
	o, _ := setupPairing(t)
	key, p := enrollment(t, o, "download")
	approve(t, o, p)
	a := o.f.app
	a.authority.Lock()
	approved, err := a.registry.pending(p.PendingID)
	a.authority.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := a.confirmApproval(approved.ID, approved.Digest); !errors.Is(err, errStaleApproval) {
		t.Fatal("confirmation replay succeeded")
	}
	cookie := login(t, o, key, p.ClientID)
	req, _ := http.NewRequest("GET", o.f.server.URL, nil)
	req.AddCookie(cookie)
	session, ok := a.sessionAccess(req)
	if !ok {
		t.Fatal("no active paired session")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer watchRevocation(ctx, session.stop, cancel)()
	var destination bytes.Buffer
	writer := downloadWriter{app: a, request: req, ctx: ctx, writer: &destination}
	if _, err := writer.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	res := o.request(t, "/api/owner/clients", map[string]string{"id": p.ClientID, "action": "revoke"}, o.credential)
	res.Body.Close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("revocation did not cancel active transfer")
	}
	if _, err := writer.Write([]byte("after")); !errors.Is(err, errDownloadCanceled) || destination.String() != "before" {
		t.Fatal("revoked download kept writing")
	}
}

func TestPairingHistoryBounds(t *testing.T) {
	o, _ := setupPairing(t)
	r := o.f.app.registry
	for i := 0; i < 280; i++ {
		_, err := r.addApproval(approval{ClientID: randomID(), Name: "History", Permission: "upload", Operation: "enroll", Expires: o.f.app.now().UnixMilli()}, o.f.app.now())
		if err != nil {
			t.Fatal(err)
		}
	}
	var count int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM approvals").Scan(&count); err != nil || count > 272 {
		t.Fatalf("unbounded approvals: %d %v", count, err)
	}
	tx, err := r.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1030; i++ {
		if _, err := tx.Exec("INSERT INTO audit(client_id,operation,old_grant,new_grant,time) VALUES('','test','','',0)"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := trimAudit(tx); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := r.db.QueryRow("SELECT COUNT(*) FROM audit").Scan(&count); err != nil || count != 1024 {
		t.Fatalf("audit retention: %d %v", count, err)
	}
}

func TestControlDatabaseFailureStopsAuthority(t *testing.T) {
	o, _ := setupPairing(t)
	o.f.app.authority.Lock()
	err := o.f.app.registry.db.Close()
	o.f.app.authority.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	result := o.f.app.control(controlRequest{Operation: "inspect", ID: randomID()})
	if result.Error == "" || !o.f.app.pairingFault.Load() {
		t.Fatal("control SQL failure did not fail closed")
	}
}
