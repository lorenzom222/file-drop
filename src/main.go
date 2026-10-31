package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func run() error {
	if os.Geteuid() == 0 {
		return errors.New("run filedrop as a regular user, not root")
	}
	c := defaultConfig()
	flag.StringVar(&c.Listen, "listen", c.Listen, "explicit receiving IP:port")
	flag.StringVar(&c.PublicURL, "public-url", c.PublicURL, "exact origin used by browsers")
	flag.StringVar(&c.Cert, "cert", "", "TLS certificate PEM")
	flag.StringVar(&c.Key, "key", "", "TLS private key PEM")
	flag.StringVar(&c.Inbox, "inbox", "", "absolute dedicated receiving directory")
	flag.StringVar(&c.OwnerListen, "owner-listen", "", "optional separate loopback IP:port for the authenticated owner page")
	flag.BoolVar(&c.DevHTTP, "dev-http", false, "unencrypted LOOPBACK ONLY, disposable test files")
	flag.BoolVar(&c.TailscaleServe, "tailscale-serve", false, "loopback HTTP backend for private Tailscale Serve HTTPS; never Funnel")
	flag.BoolVar(&c.ShareInbox, "share-inbox", false, "issue a separate invitation permitting uploads and read-only inbox metadata")
	flag.BoolVar(&c.AllowDownloads, "allow-downloads", false, "issue a separate upload/view/download invitation; requires share-inbox")
	flag.Int64Var(&c.FileLimit, "max-file-bytes", c.FileLimit, "maximum bytes per file (up to 1 GiB)")
	flag.Int64Var(&c.Budget, "budget-bytes", c.Budget, "received plus reserved bytes per run (up to 5 GiB)")
	flag.Int64Var(&c.FreeReserve, "free-reserve-bytes", c.FreeReserve, "minimum free disk space")
	flag.IntVar(&c.Concurrency, "concurrency", c.Concurrency, "global active upload limit (1-2)")
	flag.DurationVar(&c.UploadTimeout, "upload-timeout", c.UploadTimeout, "maximum upload duration")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected arguments; use filedrop -help")
	}
	tlsConfig, err := c.validate()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := openStore(c)
	if err != nil {
		return err
	}
	defer func() {
		if err := s.close(); err != nil {
			slog.Error("close inbox", "error", err)
		}
	}()
	a := newApp(c, s, ctx)
	server := &http.Server{Handler: a.handler(), TLSConfig: tlsConfig, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, BaseContext: func(net.Listener) context.Context { return ctx }}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	var ownerServer *http.Server
	var ownerListener net.Listener
	if c.OwnerListen != "" {
		ownerListener, err = net.Listen("tcp", c.OwnerListen)
		if err != nil {
			return errors.Join(fmt.Errorf("owner listen: %w", err), listener.Close())
		}
		ownerServer = &http.Server{
			Handler: a.ownerHandler(), ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10,
			BaseContext: func(net.Listener) context.Context { return ctx },
		}
	}
	if c.DevHTTP {
		fmt.Println("WARNING: loopback-only unencrypted development mode. Use disposable files.")
	}
	if c.TailscaleServe {
		fmt.Printf("Tailscale Serve mode: HTTP backend on %s; use only the private HTTPS URL.\n", c.Listen)
		fmt.Println("Requires a separately configured Tailscale Serve proxy. Proxy availability and tailnet policy are not checked by this program.")
	}
	fmt.Printf("Inbox: %s\nMax file: %d bytes; per-run budget: %d bytes; concurrency: %d\n", c.Inbox, c.FileLimit, c.Budget, c.Concurrency)
	fmt.Printf("Invitation (upload permission; expires in 10 minutes):\n%s/#%s\n", c.PublicURL, a.invitation)
	if c.ShareInbox {
		fmt.Println("WARNING: shared-inbox viewers can see names, sizes and modification times of all visible files in the inbox.")
		fmt.Printf("Shared inbox invitation (upload + view metadata; expires in 10 minutes):\n%s/#%s\n", c.PublicURL, a.viewInvitation)
	}
	if c.AllowDownloads {
		fmt.Println("WARNING: download invite holders can read all visible regular files in the inbox.")
		fmt.Printf("Download invitation (upload + view + download; expires in 10 minutes):\n%s/#%s\n", c.PublicURL, a.downloadInvitation)
	}
	if ownerServer != nil {
		fmt.Printf("Owner page (local only; single-use link expires in 10 minutes):\n%s/#%s\n", a.ownerOrigin(), a.ownerBootstrap)
	}
	done := make(chan error, 2)
	go func() {
		if c.DevHTTP || c.TailscaleServe {
			done <- server.Serve(listener)
		} else {
			done <- server.ServeTLS(listener, "", "")
		}
	}()
	if ownerServer != nil {
		go func() { done <- ownerServer.Serve(ownerListener) }()
	}
	var serveErr error
	select {
	case err := <-done:
		if !errors.Is(err, http.ErrServerClosed) {
			serveErr = err
		}
	case <-ctx.Done():
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, running := range []*http.Server{server, ownerServer} {
		if running == nil {
			continue
		}
		if err := running.Shutdown(shutdown); err != nil {
			slog.Warn("graceful shutdown exceeded deadline", "error", err)
			serveErr = errors.Join(serveErr, err, running.Close())
		}
	}
	return serveErr
}

func main() {
	if err := run(); err != nil {
		slog.Error("filedrop stopped", "error", err)
		os.Exit(1)
	}
}
