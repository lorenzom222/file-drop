package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type controlRequest struct {
	Operation string `json:"operation"`
	ID        string `json:"id"`
	Digest    string `json:"digest"`
}
type controlResponse struct {
	Error    string    `json:"error,omitempty"`
	Approval *approval `json:"approval,omitempty"`
	URL      string    `json:"url,omitempty"`
	Status   string    `json:"status,omitempty"`
}

func startControl(a *app) (*net.UnixListener, error) {
	if err := privateState(a.cfg.StateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(a.cfg.StateDir, "control.sock")
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, errors.New("unsafe control socket path")
		}
		if err := ownedByUser(info); err != nil {
			return nil, err
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0600); err != nil {
		return nil, errors.Join(err, listener.Close())
	}
	slots := make(chan struct{}, 4)
	go func() {
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					slog.Error("control listener stopped", "error", err)
				}
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			go func() {
				defer func() { <-slots }()
				defer conn.Close()
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					slog.Warn("control deadline failure", "error", err)
					return
				}
				if err := peerIsOwner(conn); err != nil {
					slog.Warn("control peer rejected", "error", err)
					return
				}
				decoder := json.NewDecoder(io.LimitReader(conn, 4096))
				decoder.DisallowUnknownFields()
				var request controlRequest
				if err := decoder.Decode(&request); err != nil {
					slog.Warn("invalid control request", "error", err)
					return
				}
				response := a.control(request)
				if err := json.NewEncoder(conn).Encode(response); err != nil {
					slog.Warn("control response interrupted", "error", err)
					return
				}
			}()
		}
	}()
	return listener, nil
}

func (a *app) control(request controlRequest) controlResponse {
	if request.Operation == "confirm" {
		if !validID(request.ID) || !validID(request.Digest) {
			return controlResponse{Error: "Invalid request ID or digest."}
		}
		_, err := a.confirmApproval(request.ID, request.Digest)
		if err != nil {
			return controlResponse{Error: err.Error()}
		}
		return controlResponse{Status: "approved"}
	}
	a.authority.Lock()
	defer a.authority.Unlock()
	if a.registry == nil || a.pairingFault.Load() || a.ctx.Err() != nil {
		return controlResponse{Error: "Registry unavailable."}
	}
	switch request.Operation {
	case "inspect":
		if !validID(request.ID) {
			return controlResponse{Error: "Invalid request ID."}
		}
		p, err := a.registry.pending(request.ID)
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				a.registryFailureLocked(err)
			}
			return controlResponse{Error: err.Error()}
		}
		if p.Status != "pending" || p.Expires <= a.now().UnixMilli() {
			return controlResponse{Error: errStaleApproval.Error()}
		}
		return controlResponse{Approval: &p}
	case "owner-link":
		a.mu.Lock()
		a.ownerBootstrap = randomID()
		a.ownerBootstrapEnd = a.now().Add(10 * time.Minute)
		link := a.ownerOrigin() + "/#" + a.ownerBootstrap
		a.mu.Unlock()
		return controlResponse{URL: link}
	case "reset-trust":
		tx, err := a.registry.db.Begin()
		if err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		defer tx.Rollback()
		epoch := randomID()
		if _, err := tx.Exec("UPDATE receiver SET epoch=?", epoch); err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		if _, err := tx.Exec("UPDATE clients SET status='revoked',generation=generation+1"); err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		if _, err := tx.Exec("UPDATE approvals SET status='superseded' WHERE status='pending'"); err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		if _, err := tx.Exec("INSERT INTO audit(client_id,operation,old_grant,new_grant,time) VALUES('','reset-trust',?,?,?)", a.registry.epoch, epoch, a.now().UnixMilli()); err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		if err := trimAudit(tx); err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		if err := tx.Commit(); err != nil {
			a.registryFailureLocked(err)
			return controlResponse{Error: err.Error()}
		}
		a.registry.epoch = epoch
		for id := range a.pairedStops {
			a.invalidateClientLocked(id)
		}
		a.challenges = make(map[string]pairingChallenge)
		a.pendingTickets = make(map[string]pendingTicket)
		a.mu.Lock()
		for key, invite := range a.invitations {
			if invite.pair {
				delete(a.invitations, key)
			}
		}
		a.mu.Unlock()
		return controlResponse{Status: "trust reset; all browsers require re-pairing"}
	default:
		return controlResponse{Error: "Invalid control operation."}
	}
}

func controlCall(state string, request controlRequest) (controlResponse, error) {
	var response controlResponse
	if err := privateState(state); err != nil {
		return response, err
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(state, "control.sock"), Net: "unix"})
	if err != nil {
		return response, err
	}
	defer conn.Close()
	if err := peerIsOwner(conn); err != nil {
		return response, err
	}
	if err := conn.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return response, err
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return response, err
	}
	if err := json.NewDecoder(io.LimitReader(conn, 8192)).Decode(&response); err != nil {
		return response, err
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}

func runControl(operation string, args []string) error {
	flags := flag.NewFlagSet(operation, flag.ContinueOnError)
	state := flags.String("state-dir", "", "absolute private registry directory")
	offline := flags.Bool("offline", false, "reset restored trust before starting the receiver (reset-trust only)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *state == "" {
		return errors.New("state-dir is required")
	}
	if *offline && operation != "reset-trust" {
		return errors.New("offline is only valid with reset-trust")
	}
	if operation == "init" {
		if flags.NArg() != 0 {
			return errors.New("unexpected init arguments")
		}
		r, err := openRegistry(*state, true)
		if err != nil {
			return err
		}
		return r.close()
	}
	if operation == "owner-link" {
		response, err := controlCall(*state, controlRequest{Operation: "owner-link"})
		if err != nil {
			return err
		}
		fmt.Println(response.URL)
		return nil
	}
	if _, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA); err != nil {
		return errors.New("confirmation requires an interactive terminal")
	}
	request := controlRequest{Operation: operation}
	if operation == "confirm" {
		if flags.NArg() != 1 || !validID(flags.Arg(0)) {
			return errors.New("confirm requires exactly one request ID")
		}
		info, err := controlCall(*state, controlRequest{Operation: "inspect", ID: flags.Arg(0)})
		if err != nil {
			return err
		}
		if info.Approval == nil {
			return errors.New("missing approval details")
		}
		p := info.Approval
		fmt.Printf("Operation: %s\nName: %q\nFingerprint: %s\nPermission: %s\nExpires: %s\nType yes to confirm: ", p.Operation, p.Name, p.Fingerprint, p.Permission, time.UnixMilli(p.Expires).Format(time.RFC3339))
		request.ID = p.ID
		request.Digest = p.Digest
	} else if operation == "reset-trust" {
		if flags.NArg() != 0 {
			return errors.New("unexpected reset arguments")
		}
		fmt.Print("Revoke every paired browser and rotate the trust epoch? Type yes: ")
	} else {
		return errors.New("unknown command")
	}
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return err
	}
	if strings.TrimSpace(answer) != "yes" {
		return errors.New("confirmation canceled")
	}
	if *offline {
		r, err := openRegistry(*state, false)
		if err != nil {
			return err
		}
		a := newApp(defaultConfig(), nil, context.Background())
		a.registry = r
		response := a.control(request)
		closeErr := r.close()
		if response.Error != "" {
			return errors.Join(errors.New(response.Error), closeErr)
		}
		if closeErr != nil {
			return closeErr
		}
		fmt.Println(response.Status)
		return nil
	}
	response, err := controlCall(*state, request)
	if err != nil {
		return err
	}
	fmt.Println(response.Status)
	return nil
}
