package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultFileLimit = int64(1 << 30)
	defaultBudget    = int64(5 << 30)
	overheadLimit    = int64(64 << 10)
)

type config struct {
	Listen, PublicURL, Cert, Key, Inbox string
	OwnerListen                         string
	DevHTTP                             bool
	TailscaleServe                      bool
	ShareInbox                          bool
	AllowDownloads                      bool
	FileLimit, Budget, FreeReserve      int64
	Concurrency                         int
	UploadTimeout                       time.Duration
}

func defaultConfig() config {
	return config{
		Listen: "127.0.0.1:8443", PublicURL: "https://127.0.0.1:8443",
		FileLimit: defaultFileLimit, Budget: defaultBudget, FreeReserve: 1 << 30,
		Concurrency: 2, UploadTimeout: 15 * time.Minute,
	}
}

func (c config) validate() (*tls.Config, error) {
	if c.OwnerListen != "" {
		host, port, err := net.SplitHostPort(c.OwnerListen)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || !ip.IsLoopback() || port == "" || port == "0" || c.OwnerListen == c.Listen {
			return nil, errors.New("owner-listen must be a separate loopback IP:port")
		}
	}
	if c.AllowDownloads && !c.ShareInbox {
		return nil, errors.New("allow-downloads requires share-inbox")
	}
	ipText, port, err := net.SplitHostPort(c.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen must be an explicit IP:port: %w", err)
	}
	ip := net.ParseIP(ipText)
	if ip == nil || ip.IsUnspecified() || port == "" || port == "0" {
		return nil, errors.New("listen requires a specific IP and nonzero port; wildcard addresses are forbidden")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil || u == nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return nil, errors.New("public-url must be an origin without path, credentials, query or fragment")
	}
	if c.Inbox == "" || !filepath.IsAbs(c.Inbox) {
		return nil, errors.New("inbox must be an absolute dedicated directory")
	}
	if c.FileLimit < 1 || c.FileLimit > defaultFileLimit || c.Budget < c.FileLimit || c.Budget > defaultBudget || c.FreeReserve < 0 || c.Concurrency < 1 || c.Concurrency > 2 || c.UploadTimeout <= 0 || c.UploadTimeout > 15*time.Minute {
		return nil, errors.New("invalid limits: max file 1 GiB, budget up to 5 GiB and >= file limit, concurrency 1-2, timeout up to 15 minutes, nonnegative free reserve")
	}
	if c.TailscaleServe {
		if c.DevHTTP || !ip.IsLoopback() || u.Scheme != "https" || !strings.HasSuffix(u.Hostname(), ".ts.net") || u.Port() != "" || c.Cert != "" || c.Key != "" {
			return nil, errors.New("tailscale-serve requires a loopback listener, an https://device.tailnet.ts.net origin without port, no dev-http and no certificate options")
		}
		return nil, nil
	}
	if u.Port() != port {
		return nil, errors.New("public-url must specify the same port as listen")
	}
	if c.DevHTTP {
		if !ip.IsLoopback() || !net.ParseIP(u.Hostname()).IsLoopback() || u.Scheme != "http" || c.Cert != "" || c.Key != "" {
			return nil, errors.New("dev-http requires loopback IP URLs/listeners, http, and no certificate options")
		}
		return nil, nil
	}
	if !ip.IsPrivate() && !ip.IsLoopback() {
		return nil, errors.New("LAN mode requires a private or loopback listen IP")
	}
	if u.Scheme != "https" || c.Cert == "" || c.Key == "" {
		return nil, errors.New("HTTPS certificate and key are required; no HTTP fallback")
	}
	pair, err := tls.LoadX509KeyPair(c.Cert, c.Key)
	if err != nil {
		return nil, fmt.Errorf("load TLS credentials: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	if err := leaf.VerifyHostname(u.Hostname()); err != nil {
		return nil, fmt.Errorf("certificate does not cover public-url: %w", err)
	}
	if now := time.Now(); now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("server certificate is not currently valid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}, nil
}
