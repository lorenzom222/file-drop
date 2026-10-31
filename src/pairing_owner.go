package main

import (
	"database/sql"
	"errors"
	"net/http"
	"time"
)

func (a *app) ownerClients(w http.ResponseWriter, r *http.Request) {
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() {
		writeError(w, 503, "registry", "Pairing registry is unavailable.")
		return
	}
	clients := []pairedClient{}
	rows, err := a.registry.db.Query("SELECT id,name,public_key,fingerprint,permission,status,generation,paired_at,last_seen FROM clients ORDER BY paired_at DESC LIMIT 128")
	if err != nil {
		a.pairingDBError(w, err)
		return
	}
	for rows.Next() {
		var c pairedClient
		if err := rows.Scan(&c.ID, &c.Name, &c.PublicKey, &c.Fingerprint, &c.Permission, &c.Status, &c.Generation, &c.PairedAt, &c.LastSeen); err != nil {
			rows.Close()
			a.pairingDBError(w, err)
			return
		}
		clients = append(clients, c)
	}
	readErr, closeErr := rows.Err(), rows.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		a.pairingDBError(w, err)
		return
	}
	pending := []approval{}
	rows, err = a.registry.db.Query("SELECT id,client_id,name,public_key,fingerprint,permission,operation,generation,receiver,epoch,expires,status,digest FROM approvals WHERE status='pending' AND expires>? ORDER BY expires LIMIT 16", a.now().UnixMilli())
	if err != nil {
		a.pairingDBError(w, err)
		return
	}
	for rows.Next() {
		var p approval
		if err := rows.Scan(&p.ID, &p.ClientID, &p.Name, &p.PublicKey, &p.Fingerprint, &p.Permission, &p.Operation, &p.Generation, &p.Receiver, &p.Epoch, &p.Expires, &p.Status, &p.Digest); err != nil {
			rows.Close()
			a.pairingDBError(w, err)
			return
		}
		pending = append(pending, p)
	}
	readErr, closeErr = rows.Err(), rows.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		a.pairingDBError(w, err)
		return
	}
	ownerJSON(w, map[string]any{"clients": clients, "pending": pending})
}

func (a *app) ownerClientChange(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID         string `json:"id"`
		Action     string `json:"action"`
		Name       string `json:"name"`
		Permission string `json:"permission"`
	}
	if !decodeOwnerRequest(w, r, &request) {
		return
	}
	if !validID(request.ID) {
		writeError(w, 400, "id", "Invalid paired browser ID.")
		return
	}
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() {
		writeError(w, 503, "registry", "Pairing registry is unavailable.")
		return
	}
	if request.Action == "decline" {
		result, err := a.registry.db.Exec("UPDATE approvals SET status='declined' WHERE id=? AND status='pending'", request.ID)
		if err != nil {
			a.pairingDBError(w, err)
			return
		}
		n, err := result.RowsAffected()
		if err != nil {
			a.pairingDBError(w, err)
			return
		}
		if n != 1 {
			writeError(w, 409, "stale", "Request is no longer pending.")
			return
		}
		ownerJSON(w, map[string]any{"status": "declined"})
		return
	}
	client, err := a.registry.client(request.ID)
	if err != nil {
		a.pairingDBError(w, err)
		return
	}
	if client.Status != "active" {
		writeError(w, 409, "stale", "Browser is no longer active.")
		return
	}
	switch request.Action {
	case "revoke":
		if err := a.registry.change(client.ID, client.Name, client.Permission, true, a.now()); err != nil {
			a.pairingDBError(w, err)
			return
		}
		a.invalidateClientLocked(client.ID)
		ownerJSON(w, map[string]any{"status": "revoked"})
	case "edit":
		rank := permissionRank(request.Permission)
		if rank == 0 || !validLabel(request.Name) || (rank >= 2 && !a.cfg.ShareInbox) || (rank >= 3 && !a.cfg.AllowDownloads) {
			writeError(w, 400, "permission", "Invalid name or disabled permission.")
			return
		}
		if rank > permissionRank(client.Permission) {
			p, err := a.registry.addApproval(approval{ClientID: client.ID, Name: request.Name, PublicKey: client.PublicKey, Fingerprint: client.Fingerprint, Permission: request.Permission, Operation: "increase", Generation: client.Generation, Expires: a.now().Add(10 * time.Minute).UnixMilli()}, a.now())
			if err != nil {
				a.pairingDBError(w, err)
				return
			}
			ownerJSON(w, map[string]any{"status": "pending", "request_id": p.ID})
			return
		}
		if err := a.registry.change(client.ID, request.Name, request.Permission, false, a.now()); err != nil {
			a.pairingDBError(w, err)
			return
		}
		a.invalidateClientLocked(client.ID)
		ownerJSON(w, map[string]any{"status": "updated"})
	default:
		writeError(w, 400, "action", "Choose edit, revoke or decline.")
	}
}

func (a *app) confirmApproval(id, digest string) (string, error) {
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() || a.ctx.Err() != nil {
		return "", errPairingAuth
	}
	p, err := a.registry.pending(id)
	if err != nil {
		return "", err
	}
	if (permissionRank(p.Permission) >= 2 && !a.cfg.ShareInbox) || (permissionRank(p.Permission) >= 3 && !a.cfg.AllowDownloads) {
		return "", errStaleApproval
	}
	clientID, err := a.registry.confirm(id, digest, a.now())
	if err != nil {
		if !errors.Is(err, errStaleApproval) && !errors.Is(err, sql.ErrNoRows) {
			a.registryFailureLocked(err)
		}
		return "", err
	}
	a.invalidateClientLocked(clientID)
	return clientID, nil
}
