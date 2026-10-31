package main

import (
	"errors"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func ownedByUser(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || (!info.IsDir() && stat.Nlink != 1) {
		return errors.New("state must be owned by this user and not hard-linked")
	}
	return nil
}
func noFollowFlag() int { return unix.O_NOFOLLOW }

func peerIsOwner(conn *net.UnixConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err := raw.Control(func(fd uintptr) {
		credentials, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			inner = err
			return
		}
		if credentials.Uid != uint32(os.Geteuid()) {
			inner = errors.New("control socket peer is not the receiver user")
		}
	}); err != nil {
		return err
	}
	return inner
}
