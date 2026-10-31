package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func identityOf(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, fmt.Errorf("unsupported filesystem identity")
	}
	return fileIdentity{Device: uint64(uint32(stat.Dev)), Inode: stat.Ino}, nil
}

func (s *store) openDownload(offer downloadOffer) (*os.File, error) {
	if !safeName(offer.Name) {
		return nil, errOfferChanged
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return nil, err
	}
	// Open a single validated basename with kernel-level no-follow semantics.
	fd, openErr := unix.Openat(int(dir.Fd()), offer.Name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err := dir.Close(); err != nil {
		if openErr == nil {
			return nil, errors.Join(err, unix.Close(fd))
		}
		return nil, errors.Join(err, openErr)
	}
	err = openErr
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, unix.ELOOP) {
			return nil, errOfferChanged
		}
		return nil, err
	}
	file := os.NewFile(uintptr(fd), offer.Name)
	info, err := file.Stat()
	if err != nil {
		return nil, errors.Join(err, file.Close())
	}
	identity, err := identityOf(info)
	if err != nil || !info.Mode().IsRegular() || identity != offer.Identity || info.Size() != offer.Bytes || info.ModTime().UnixNano() != offer.ModifiedNano {
		return nil, errors.Join(errOfferChanged, err, file.Close())
	}
	return file, nil
}

func lockInbox(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func freeBytes(f *os.File) (int64, error) {
	var stat unix.Statfs_t
	if err := unix.Fstatfs(int(f.Fd()), &stat); err != nil {
		return 0, err
	}
	return int64(stat.Bavail) * int64(stat.Bsize), nil
}

func quarantine(f *os.File) error {
	value := fmt.Sprintf("0081;%x;LocalFileDrop;", time.Now().Unix())
	return unix.Fsetxattr(int(f.Fd()), "com.apple.quarantine", []byte(value), 0)
}
