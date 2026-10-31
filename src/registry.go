package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	_ "modernc.org/sqlite"
)

var errPairingAuth = errors.New("pairing authorization denied")
var errStaleApproval = errors.New("approval expired, completed or superseded")

type registry struct {
	db              *sql.DB
	lock            *os.File
	receiver, epoch string
}

type pairedClient struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Permission  string `json:"permission"`
	Status      string `json:"status"`
	Generation  int64  `json:"generation"`
	PairedAt    int64  `json:"paired_at"`
	LastSeen    int64  `json:"last_seen"`
}

type approval struct {
	ID          string `json:"id"`
	ClientID    string `json:"client_id"`
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"fingerprint"`
	Permission  string `json:"permission"`
	Operation   string `json:"operation"`
	Generation  int64  `json:"generation"`
	Receiver    string `json:"receiver"`
	Epoch       string `json:"epoch"`
	Expires     int64  `json:"expires"`
	Status      string `json:"status"`
	Digest      string `json:"digest"`
}

func permissionRank(permission string) int {
	switch permission {
	case "upload":
		return 1
	case "view":
		return 2
	case "download":
		return 3
	default:
		return 0
	}
}

func validLabel(name string) bool {
	if strings.TrimSpace(name) != name || name == "" || len(name) > 80 {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) {
			return false
		}
	}
	return true
}

func privateState(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("state-dir must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if resolved != filepath.Clean(path) {
		return errors.New("state directory must not use symlinks")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm() != 0700 {
		return errors.New("state directory must have mode 0700")
	}
	return ownedByUser(info)
}

func openRegistry(path string, initialize bool) (*registry, error) {
	if initialize {
		if !filepath.IsAbs(path) {
			return nil, errors.New("state-dir must be absolute")
		}
		if err := os.MkdirAll(path, 0700); err != nil {
			return nil, err
		}
	}
	if err := privateState(path); err != nil {
		return nil, fmt.Errorf("private state: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(path, "registry.lock"), os.O_CREATE|os.O_RDWR|noFollowFlag(), 0600)
	if err != nil {
		return nil, err
	}
	r := &registry{lock: lock}
	fail := func(err error) (*registry, error) { return nil, errors.Join(err, r.close()) }
	if err := lockInbox(lock); err != nil {
		return fail(fmt.Errorf("state already in use: %w", err))
	}
	dbPath := filepath.Join(path, "registry.sqlite")
	if initialize {
		f, err := os.OpenFile(dbPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if err != nil {
			return fail(fmt.Errorf("explicit initialization refused: %w", err))
		}
		if err := f.Close(); err != nil {
			return fail(err)
		}
	}
	info, err := os.Lstat(dbPath)
	if err != nil {
		return fail(fmt.Errorf("registry missing; initialize explicitly: %w", err))
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return fail(errors.New("registry must be a mode-0600 regular file"))
	}
	if err := ownedByUser(info); err != nil {
		return fail(err)
	}
	u := url.URL{Scheme: "file", Path: dbPath, RawQuery: "mode=rw"}
	r.db, err = sql.Open("sqlite", u.String())
	if err != nil {
		return fail(err)
	}
	r.db.SetMaxOpenConns(1)
	if _, err := r.db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=DELETE; PRAGMA foreign_keys=ON; PRAGMA synchronous=FULL;`); err != nil {
		return fail(err)
	}
	if initialize {
		_, err = r.db.Exec(`CREATE TABLE receiver (id TEXT NOT NULL, epoch TEXT NOT NULL, version INTEGER NOT NULL);
CREATE TABLE clients (id TEXT PRIMARY KEY,name TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,permission TEXT NOT NULL,status TEXT NOT NULL,generation INTEGER NOT NULL,paired_at INTEGER NOT NULL,last_seen INTEGER NOT NULL);
CREATE TABLE approvals (id TEXT PRIMARY KEY,client_id TEXT NOT NULL,name TEXT NOT NULL,public_key TEXT NOT NULL,fingerprint TEXT NOT NULL,permission TEXT NOT NULL,operation TEXT NOT NULL,generation INTEGER NOT NULL,receiver TEXT NOT NULL,epoch TEXT NOT NULL,expires INTEGER NOT NULL,status TEXT NOT NULL,digest TEXT NOT NULL);
CREATE TABLE audit (id INTEGER PRIMARY KEY,client_id TEXT NOT NULL,operation TEXT NOT NULL,old_grant TEXT NOT NULL,new_grant TEXT NOT NULL,time INTEGER NOT NULL);`)
		if err != nil {
			return fail(err)
		}
		if _, err := r.db.Exec("INSERT INTO receiver VALUES (?,?,1)", randomID(), randomID()); err != nil {
			return fail(err)
		}
	}
	var check string
	if err := r.db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil || check != "ok" {
		return fail(errors.Join(errors.New("registry integrity check failed"), err))
	}
	var version int
	if err := r.db.QueryRow("SELECT id,epoch,version FROM receiver").Scan(&r.receiver, &r.epoch, &version); err != nil {
		return fail(err)
	}
	if version != 1 || !validID(r.receiver) || !validID(r.epoch) {
		return fail(errors.New("unsupported registry identity/schema"))
	}
	// Pending handshakes cannot survive a process restart.
	if _, err := r.db.Exec("UPDATE approvals SET status='expired' WHERE status='pending'"); err != nil {
		return fail(err)
	}
	return r, nil
}

func (r *registry) close() error {
	var errs []error
	if r.db != nil {
		errs = append(errs, r.db.Close())
	}
	if r.lock != nil {
		errs = append(errs, r.lock.Close())
	}
	return errors.Join(errs...)
}

func validID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func (r *registry) client(id string) (pairedClient, error) {
	var c pairedClient
	err := r.db.QueryRow("SELECT id,name,public_key,fingerprint,permission,status,generation,paired_at,last_seen FROM clients WHERE id=?", id).Scan(&c.ID, &c.Name, &c.PublicKey, &c.Fingerprint, &c.Permission, &c.Status, &c.Generation, &c.PairedAt, &c.LastSeen)
	return c, err
}

func (r *registry) pending(id string) (approval, error) {
	var p approval
	err := r.db.QueryRow("SELECT id,client_id,name,public_key,fingerprint,permission,operation,generation,receiver,epoch,expires,status,digest FROM approvals WHERE id=?", id).Scan(&p.ID, &p.ClientID, &p.Name, &p.PublicKey, &p.Fingerprint, &p.Permission, &p.Operation, &p.Generation, &p.Receiver, &p.Epoch, &p.Expires, &p.Status, &p.Digest)
	return p, err
}

func (r *registry) addApproval(p approval, now time.Time) (approval, error) {
	if _, err := r.db.Exec("DELETE FROM approvals WHERE (status!='pending' OR expires<=?) AND id NOT IN (SELECT id FROM approvals ORDER BY expires DESC LIMIT 256)", now.UnixMilli()); err != nil {
		return p, err
	}
	var count int
	if err := r.db.QueryRow("SELECT COUNT(*) FROM approvals WHERE status='pending' AND expires>?", now.UnixMilli()).Scan(&count); err != nil {
		return p, err
	}
	if count >= 16 {
		return p, errCapacity
	}
	if err := r.db.QueryRow("SELECT COUNT(*) FROM clients").Scan(&count); err != nil {
		return p, err
	}
	if p.Operation == "enroll" && count >= 128 {
		return p, errCapacity
	}
	p.ID = randomID()
	p.Receiver = r.receiver
	p.Epoch = r.epoch
	p.Status = "pending"
	encoded, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	hash := sha256.Sum256(encoded)
	p.Digest = hex.EncodeToString(hash[:])
	_, err = r.db.Exec("INSERT INTO approvals VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", p.ID, p.ClientID, p.Name, p.PublicKey, p.Fingerprint, p.Permission, p.Operation, p.Generation, p.Receiver, p.Epoch, p.Expires, p.Status, p.Digest)
	return p, err
}

func (r *registry) confirm(id, digest string, now time.Time) (string, error) {
	p, err := r.pending(id)
	if err != nil {
		return "", err
	}
	if p.Status != "pending" || p.Expires <= now.UnixMilli() || p.Digest != digest || p.Receiver != r.receiver || p.Epoch != r.epoch {
		return "", errStaleApproval
	}
	if p.Operation == "increase" {
		c, err := r.client(p.ClientID)
		if err != nil {
			return "", err
		}
		if c.Status != "active" || c.Generation != p.Generation || permissionRank(p.Permission) <= permissionRank(c.Permission) {
			return "", errStaleApproval
		}
	}
	tx, err := r.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if p.Operation == "enroll" {
		_, err = tx.Exec("INSERT INTO clients VALUES (?,?,?,?,?,'active',1,?,?)", p.ClientID, p.Name, p.PublicKey, p.Fingerprint, p.Permission, now.UnixMilli(), now.UnixMilli())
	} else if p.Operation == "increase" {
		_, err = tx.Exec("UPDATE clients SET name=?,permission=?,generation=generation+1 WHERE id=?", p.Name, p.Permission, p.ClientID)
	} else {
		return "", errStaleApproval
	}
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec("UPDATE approvals SET status='approved' WHERE id=?", id); err != nil {
		return "", err
	}
	if _, err := tx.Exec("INSERT INTO audit(client_id,operation,old_grant,new_grant,time) VALUES(?,?,?,?,?)", p.ClientID, p.Operation, "", p.Permission, now.UnixMilli()); err != nil {
		return "", err
	}
	if err := trimAudit(tx); err != nil {
		return "", err
	}
	return p.ClientID, tx.Commit()
}

func (r *registry) change(id, name, permission string, revoke bool, now time.Time) error {
	c, err := r.client(id)
	if err != nil {
		return err
	}
	if c.Status != "active" {
		return errStaleApproval
	}
	status := c.Status
	if revoke {
		status = "revoked"
	}
	tx, err := r.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec("UPDATE clients SET name=?,permission=?,status=?,generation=generation+1 WHERE id=?", name, permission, status, id); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE approvals SET status='superseded' WHERE client_id=? AND status='pending'", id); err != nil {
		return err
	}
	operation := "reduce"
	if revoke {
		operation = "revoke"
	}
	if _, err := tx.Exec("INSERT INTO audit(client_id,operation,old_grant,new_grant,time) VALUES(?,?,?,?,?)", id, operation, c.Permission, permission, now.UnixMilli()); err != nil {
		return err
	}
	if err := trimAudit(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func trimAudit(tx *sql.Tx) error {
	_, err := tx.Exec("DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 1024)")
	return err
}
