package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

var errCapacity = errors.New("upload capacity exhausted")
var errInboxLimit = errors.New("inbox listing entry limit exceeded")

const inboxEntryLimit = 1000

type inboxFile struct {
	ID         string    `json:"id,omitempty"`
	Name       string    `json:"name"`
	Bytes      int64     `json:"bytes"`
	ModifiedAt time.Time `json:"modified_at"`
	identity   fileIdentity
}

func (s *store) listInbox(ctx context.Context) ([]inboxFile, error) {
	dir, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	entries, readErr := dir.ReadDir(inboxEntryLimit + 1)
	closeErr := dir.Close()
	if readErr != nil && readErr != io.EOF {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > inboxEntryLimit {
		return nil, errInboxLimit
	}
	files := make([]inboxFile, 0, len(entries))
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !safeName(entry.Name()) {
			continue
		}
		info, err := s.root.Lstat(entry.Name())
		if errors.Is(err, fs.ErrNotExist) {
			continue // A file deleted while taking the snapshot is no longer in the inbox.
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		identity, err := identityOf(info)
		if err != nil {
			return nil, err
		}
		files = append(files, inboxFile{Name: entry.Name(), Bytes: info.Size(), ModifiedAt: info.ModTime(), identity: identity})
	}
	sort.Slice(files, func(i, j int) bool {
		if files[i].ModifiedAt.Equal(files[j].ModifiedAt) {
			return files[i].Name < files[j].Name
		}
		return files[i].ModifiedAt.After(files[j].ModifiedAt)
	})
	return files, nil
}

type store struct {
	root           *os.Root
	lock           *os.File
	mu             sync.Mutex
	used, reserved int64
	active         int
	cfg            config
}

func randomID() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func openStore(c config) (*store, error) {
	if err := os.MkdirAll(c.Inbox, 0700); err != nil {
		return nil, fmt.Errorf("create inbox: %w", err)
	}
	r, err := os.OpenRoot(c.Inbox)
	if err != nil {
		return nil, err
	}
	s := &store{root: r, cfg: c}
	fail := func(err error) (*store, error) { return nil, errors.Join(err, s.close()) }
	// Hold the lock throughout the run so startup cleanup cannot race another server.
	if info, err := r.Lstat(".filedrop-lock"); err == nil && !info.Mode().IsRegular() {
		return fail(errors.New("unsafe inbox lock"))
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fail(err)
	}
	s.lock, err = r.OpenFile(".filedrop-lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return fail(err)
	}
	if err = lockInbox(s.lock); err != nil {
		return fail(fmt.Errorf("inbox already in use or cannot lock: %w", err))
	}
	if err = r.Mkdir(".filedrop-staging", 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fail(err)
	}
	info, err := r.Lstat(".filedrop-staging")
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return fail(errors.New("staging must be a private, real directory"))
	}
	dir, err := r.Open(".filedrop-staging")
	if err != nil {
		return fail(err)
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil {
		return fail(readErr)
	}
	if closeErr != nil {
		return fail(closeErr)
	}
	for _, entry := range entries {
		if !ownedStage(entry.Name()) || !entry.Type().IsRegular() {
			return fail(errors.New("unexpected staging entry; inspect it before restarting"))
		}
		if err := r.Remove(filepath.Join(".filedrop-staging", entry.Name())); err != nil {
			return fail(fmt.Errorf("clean stale upload: %w", err))
		}
	}
	return s, nil
}

func ownedStage(name string) bool {
	if !strings.HasPrefix(name, "upload-") || len(name) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(name, "upload-"))
	return err == nil
}

func (s *store) close() error {
	var errs []error
	if s.lock != nil {
		errs = append(errs, s.lock.Close())
	}
	if s.root != nil {
		errs = append(errs, s.root.Close())
	}
	return errors.Join(errs...)
}

func (s *store) reserve() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active >= s.cfg.Concurrency || s.used+s.reserved+s.cfg.FileLimit > s.cfg.Budget {
		return errCapacity
	}
	s.active++
	s.reserved += s.cfg.FileLimit
	return nil
}

func (s *store) release(committed int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active--
	s.reserved -= s.cfg.FileLimit
	s.used += committed
}

func (s *store) spaceOK(f *os.File, next int64) error {
	free, err := freeBytes(f)
	if err != nil {
		return fmt.Errorf("check disk space: %w", err)
	}
	s.mu.Lock()
	active := s.active
	s.mu.Unlock()
	// Reserve a chunk for each concurrent writer as well as the configured floor.
	if free < s.cfg.FreeReserve+int64(active)*next {
		return errCapacity
	}
	return nil
}

func safeName(name string) bool {
	if !utf8.ValidString(name) || name == "" || len(name) > 180 || strings.HasPrefix(name, ".") || strings.TrimSpace(name) != name || strings.HasSuffix(name, ".") {
		return false
	}
	for _, c := range name {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || strings.ContainsRune(`/\:*?"<>|`, c) {
			return false
		}
	}
	base := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" || (len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '0' && base[3] <= '9') {
		return false
	}
	return true
}

func (s *store) finalize(stage, name string) (string, error) {
	for attempt := 0; attempt < 8; attempt++ {
		candidate := name
		if attempt > 0 {
			ext := filepath.Ext(name)
			candidate = strings.TrimSuffix(name, ext) + "-" + randomID()[:12] + ext
		}
		// A hard link publishes atomically and cannot replace an existing destination.
		if err := s.root.Link(stage, candidate); errors.Is(err, fs.ErrExist) {
			continue
		} else if err != nil {
			return "", err
		}
		return candidate, nil
	}
	return "", errors.New("could not allocate a distinct destination filename")
}
