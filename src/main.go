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
	done := make(chan error, 1)
	go func() {
		if c.DevHTTP || c.TailscaleServe {
			done <- server.Serve(listener)
		} else {
			done <- server.ServeTLS(listener, "", "")
		}
	}()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			slog.Warn("graceful shutdown exceeded deadline", "error", err)
			if closeErr := server.Close(); closeErr != nil {
				return closeErr
			}
			return err
		}
		return nil
	}
}

func main() {
	if err := run(); err != nil {
		slog.Error("filedrop stopped", "error", err)
		os.Exit(1)
	}
}
