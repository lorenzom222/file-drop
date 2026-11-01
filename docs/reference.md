# File Drop technical reference

A file-transfer app with one receiving computer and browser clients. Clients use an invitation to upload, list or download files according to their permissions. Files are stored in a dedicated folder on the receiver, not in a cloud storage service.

For setup and everyday use, start with the [README](../README.md). Commands here are run from the repository root.

## Project layout

```text
src/
  main.go                 CLI and process lifecycle
  config.go               Configuration and TLS validation
  server.go               HTTP routes, sessions and permissions
  storage.go              Inbox, staging and upload capacity
  storage_darwin.go       macOS filesystem operations
  download.go             Signed offers and download streaming
  owner.go                Local owner login, links and QR codes
  pairing.go              Browser proof and current authorization
  registry.go             SQLite pairing state
  control.go              Local terminal confirmations
  *_test.go               Go tests beside the implementation
  ui/
    index.html            Static interface
    style.css             Local font and simple styling
    fonts/                JetBrains Mono WOFF2 and license
    app.ts                Browser behavior
    owner.html / owner.ts  Local Link device page
    pairing.ts            IndexedDB keys and reconnect proof
    dist/                 Generated JavaScript (ignored)
bin/                      Compiled executable (ignored)
go.mod / go.sum            Go dependencies
package.json / lock file   Frontend build dependencies
tsconfig.json              TypeScript settings
```

## Servers and clients

With Tailscale Serve, the upload path is:

```text
Phone / other PC
      │
      │ HTTPS over Tailscale
      ▼
Tailscale Serve
      │
      │ HTTP over local loopback
      ▼
Go receiver
      │
      ▼
Mac's inbox folder
```

| Component | Responsibility |
|---|---|
| Go receiver | Serves the client UI and optional local owner UI; issues invitations and sessions; checks permissions; streams uploads/downloads; lists inbox metadata; enforces storage and transfer limits. |
| Tailscale Serve, when used | Provides private HTTPS and proxies requests to Go over loopback on the receiving computer. Does not manage the app's invitations or files. |
| Browser client | Selects files, uploads them, shows progress/errors, polls the inbox, and starts native browser downloads. Does not run a background receiver or automatically save files when closed. |
| Local inbox | Stores accepted files on the receiver. Files remain until the receiver's user removes them. |

**One Go server, multiple browser clients.** File contents can move in both directions:

```text
Client -> receiver: upload into the inbox
Receiver -> client: authorized download from the inbox
```

This is a client/server relationship, not a peer-to-peer mesh. A browser cannot push files into another browser's filesystem. A second receiving PC would need its own receiver.

## HTTP API

| Endpoint | Purpose | Required permission |
|---|---|---|
| `POST /api/session` | Exchange an invitation for a session cookie and permission flags. | Valid invitation |
| `POST /api/uploads` | Stream one multipart file into the inbox; return its stored name and size. | Upload |
| `GET /api/inbox` | Return file metadata and signed download offers when permitted. | View inbox |
| `GET /api/downloads/{id}` | Stream an offered file as an attachment. | Download + valid session-bound offer |
| `GET /api/pairing/info` | Return whether pairing is enabled and the receiver identity/origin. | Same-origin request marker |
| `POST /api/pairing/challenge` | Issue a short-lived enrollment/login challenge. | Enrollment invitation or registered client ID |
| `POST /api/pairing/proof` | Verify the key signature; create a pending enrollment or session. | Valid, unused key proof |
| `POST /api/pairing/status` | Read approval progress. | Matching short-lived pending-request ticket |

The optional owner listener has its own API, not accessible through the guest server:

| Endpoint | Purpose | Required permission |
|---|---|---|
| `POST /api/owner/session` | Exchange a single-use startup owner link for a bearer credential. | Valid owner bootstrap |
| `GET /api/owner/status` | Return the access levels enabled by receiver flags. | Owner |
| `POST /api/owner/invitations` | Create or renew one permission's temporary invitation. | Owner |
| `POST /api/owner/qr` | Generate a PNG QR code for the exact current invitation. | Owner |
| `GET /api/owner/clients` | List paired browsers and pending approvals. | Owner |
| `POST /api/owner/clients` | Rename, reduce, revoke, decline, or propose an increase. | Owner; increases still require terminal confirmation |

The receiver also serves the static page, JavaScript, stylesheet and local font. Upload and inbox responses are JSON; downloads are binary streams. Failures use non-success HTTP status codes.

The server uses Go's `net/http`, multipart parsing, directory-relative filesystem APIs and cryptographic primitives. Browser clients use `fetch`, `XMLHttpRequest` for upload progress, and native file selection/downloads. Tailscale supplies encrypted device connectivity and Serve supplies HTTPS; neither replaces the app's permission checks.

## Build

The receiver requires macOS, Go 1.26+ and Node/npm to build. Clients need a browser. Dependencies include TypeScript, `golang.org/x/sys`, SQLite via `modernc.org/sqlite`, and `github.com/yeqown/go-qrcode/v2` for local QR encoding. Playwright is used for E2E tests. The bundled font's source and license are in [src/ui/fonts/](../src/ui/fonts/README.md).

```sh
npm ci
npm run build
go build -o bin/filedrop ./src
```

The frontend is embedded in the executable. Rebuild TypeScript before building Go after UI changes.

## Run through Tailscale

Install and authorize Tailscale on the receiver and each client. Enable MagicDNS and HTTPS as required by Serve, and restrict receiver access using your tailnet policy.

Check existing Serve configuration before changing it. In one terminal:

```sh
tailscale serve --https=443 http://127.0.0.1:8443
```

Use **Serve, not Funnel**. Funnel is public internet exposure. Verify `tailscale serve status` and `tailscale funnel status`.

In another terminal, using the exact HTTPS origin printed by Serve:

```sh
./bin/filedrop \
  -tailscale-serve \
  -share-inbox \
  -allow-downloads \
  -owner-listen 127.0.0.1:18445 \
  -listen 127.0.0.1:8443 \
  -public-url https://receiver.example-tailnet.ts.net \
  -inbox "$HOME/FileDropInbox"
```

Open the appropriate invitation printed by Go. Keep both programs running and the receiver awake.

### Link a device from the owner page

`-owner-listen` enables a separate, local-only owner page. Open the **owner link** printed in the receiver's terminal on that same computer. The link is single-use and expires in 10 minutes; it grants an eight-hour owner session, stored in that tab's session storage. Refreshing the owner tab retains its session when browser storage is available. Do not share or proxy this page, or its bootstrap link.

1. Select **Upload only**, **Upload and view inbox**, or **Upload, view and download**. Only enabled receiver permissions are selectable.
2. Select **Create link** under **Link device**.
3. Copy the invitation to another device, or show its QR code and scan with your phone.
4. Connect that device to your tailnet before opening the invitation.
5. Create a new link when it expires; no receiver restart is needed.

Each new link lasts 10 minutes and replaces the previous invitation for that access level. Existing guest sessions retain their original permission and expiration; renewing an invitation does not disconnect or upgrade them. Other access levels' invitations are unchanged.

This is temporary access, **not permanent device identity or pairing**. Anyone with the guest link can enroll during its validity window. The owner page never appears on the guest server. Guest session credentials cannot create invitations, and QR generation does not send URLs to an external service.

Owner bootstrap authentication, exact Host/Origin checks, request markers and a separate loopback listener protect management access. The browser keeps its bearer credential in session storage on the owner origin, not in guest cookies or URLs. If storage is blocked, keep the owner tab open. With persistent state enabled, `owner-link` can issue a fresh bootstrap without restarting; otherwise expired owner sessions require a receiver restart.

### Remember a browser

Persistent pairing is optional. Initialize a private state directory outside the inbox once:

```sh
./bin/filedrop init -state-dir "$HOME/Library/Application Support/FileDrop"
```

Start the receiver with the existing options plus:

```sh
-state-dir "$HOME/Library/Application Support/FileDrop"
```

Pairing requires the local owner listener. State must be a real, owner-only directory (mode 0700); it cannot be inside or contain the inbox. Missing or corrupt registry state is an error, not an automatic reset.

1. On the owner page, select **Remember browser**, enter a name and choose access.
2. Create the single-use link or QR, then open it on the client.
3. Select **Request pairing**. Compare the displayed key fingerprint with the pending request on the owner page.
4. Run the pending request's confirmation command in a terminal on the receiver, and type `yes`.
5. Later, open the ordinary receiver URL. That browser profile reconnects with its saved key.

The browser keeps a nonextractable P-256 signing key in IndexedDB; the receiver stores its public key and permissions in SQLite. Pairing lasts until revoked, but sessions still expire after 30 minutes. Storage clearing or a different browser profile requires re-pairing. This identifies a browser credential, not a physical device. New enrollment uses a separate candidate key until approval and login succeed, preserving any existing pairing if an enrollment fails.

The **Paired browsers** section lets the owner rename browsers, reduce permissions, or revoke access. Permission increases require another terminal confirmation. Existing sessions never gain permissions automatically; changes invalidate sessions and download offers. Revocation persists across restart and cancels active transfers, but cannot retract bytes already delivered.

Unsaved owner edits are preserved across polling. Save access applies one browser's edits; Cancel unsaved edits reloads the server state without applying them.

Local CLI operations use a private Unix socket and check peer UID:

```sh
./bin/filedrop confirm -state-dir "$HOME/Library/Application Support/FileDrop" REQUEST_ID
./bin/filedrop owner-link -state-dir "$HOME/Library/Application Support/FileDrop"
./bin/filedrop reset-trust -state-dir "$HOME/Library/Application Support/FileDrop"
```

`owner-link` creates a fresh, single-use owner bootstrap without restarting. `reset-trust` requires interactive confirmation, rotates the trust epoch and revokes all browsers. Direct approval/reset HTTP endpoints do not exist.

When restoring a state backup, stop the receiver, restore its private files, then run this **before** starting it:

```sh
./bin/filedrop reset-trust -offline -state-dir "$HOME/Library/Application Support/FileDrop"
```

Offline reset refuses an in-use registry. Starting a restored registry without this reset is unsupported and can resurrect old trust; arbitrary filesystem rollback cannot be detected.

Storage is bounded to 128 saved client identities (including revoked ones), 16 live approvals, 64 challenges and 32 sessions. Completed/expired approval history keeps the latest 256 records, and audit history keeps the latest 1,024 events.

Temporary links remain available. They do not implicitly pair a browser or gain persistent permissions.

```mermaid
sequenceDiagram
    %%{init: {"theme": "dark"}}%%
    participant Owner as Local owner browser
    participant Management as Owner listener
    participant Guest as Guest browser
    participant Receiver as Guest listener
    Owner->>Management: POST /api/owner/session with single-use bootstrap
    Management-->>Owner: Owner bearer credential
    Owner->>Management: POST /api/owner/invitations with permission
    Management-->>Owner: Guest link and expiration
    Owner->>Management: POST /api/owner/qr with exact invitation
    Management-->>Owner: Locally generated PNG
    Note over Owner,Guest: Owner shares the guest link or displays its QR.
    Guest->>Receiver: POST /api/session with guest invitation
    Receiver-->>Guest: Scoped guest session cookie
```

Go listens only on loopback in this mode. Serve terminates HTTPS; session cookies remain Secure. The app validates the configured public Host and browser origin rather than trusting forwarded identity headers.

Tailscale uses cloud coordination and can relay encrypted traffic when a direct connection fails. It does not provide cloud file storage for this app. This is **not guaranteed LAN-only or fully offline**. HTTPS certificate issuance publishes the device's certificate hostname in certificate-transparency logs; choose a non-sensitive name. Never share private keys.

Sources: [Serve](https://tailscale.com/docs/features/tailscale-serve), [encrypted relays](https://tailscale.com/docs/reference/derp-servers), [HTTPS certificates](https://tailscale.com/docs/how-to/set-up-https-certificates).

### Other run modes

Direct LAN HTTPS requires a certificate covering the exact public hostname/IP and client trust in its issuer. Do not bypass warnings:

```sh
./bin/filedrop \
  -listen 192.168.1.50:8443 \
  -public-url https://192.168.1.50:8443 \
  -cert /path/to/server.pem \
  -key /path/to/server-key.pem \
  -inbox "$HOME/FileDropInbox"
```

For disposable loopback tests only:

```sh
./bin/filedrop \
  -dev-http \
  -listen 127.0.0.1:8443 \
  -public-url http://127.0.0.1:8443 \
  -inbox "$HOME/FileDropTestInbox"
```

Development HTTP cannot bind to the LAN. Do not tunnel or publicly proxy it. Direct HTTPS is mandatory outside the explicitly configured Tailscale loopback backend.

## Permissions

| Invitation | Receiver flags | Grants |
|---|---|---|
| Upload-only | Default | Deposit files; no listing or downloads. |
| Shared inbox | `-share-inbox` | Upload and view all visible inbox file metadata. |
| Download | `-share-inbox -allow-downloads` | Upload, view and download all visible inbox files. |

Each invitation is a separate unpredictable secret, reusable for 10 minutes. Browser sessions last 30 minutes, with a maximum of 32 sessions. Permission is captured at session creation: an upload-only or metadata-only session never automatically gains download access.

The UI reads the invitation from the URL fragment, removes it, and exchanges it for an HttpOnly, SameSite=Strict cookie. HTTPS cookies are Secure. Reopen a guest invitation after refreshing; changing its fragment reconnects the updated UI. The authenticated owner page can renew expired guest links without restarting. Restarting revokes all sessions and generates new invitations.

Shared access applies to the **whole visible inbox**, not only one client's uploads, including files present before startup. Keep sensitive or unrelated files elsewhere. No remote file deletion, arbitrary directory browsing, or guest-accessible administrative API is provided.

## Request sequence

One browser request travels through Tailscale Serve to the Go receiver. Serve handles HTTPS; Go handles application permissions. The same return path carries responses.

```mermaid
sequenceDiagram
    %%{init: {"theme": "dark"}}%%
    participant Client as Browser
    participant Proxy as Tailscale Serve
    participant App as Go receiver
    Client->>Client: authenticate(): read and remove URL fragment
    Client->>Proxy: HTTPS POST /api/session {invitation}
    Proxy->>App: HTTP over loopback with original Host and Origin
    App->>App: session(w, r): validate invitation and set permissions
    App-->>Proxy: Session cookie + permission flags
    Proxy-->>Client: HTTPS response
    Note over Client,App: Subsequent requests use the session cookie.<br/>Uploads and inbox requests also use the request marker.
```

## Methods and transformed data

Each diagram covers **one operation**. Read top to bottom: solid arrows are calls or outgoing data; dashed arrows are returned values. Participants are the owning module, Go struct, or file handle; arrow labels name methods and parameters.

Dark participant groups identify ownership: **blue = browser, green = Go application, amber = storage**. Tailscale's unchanged transport hop is omitted below. All operations first pass Host/origin checks and session authorization; failed checks return an error before file access.

### 1. Upload: browser bytes become a stored file

The browser sends one multipart file per request. Receiving progress is not success: the server returns 201 only after publication.

```mermaid
sequenceDiagram
    %%{init: {"theme": "dark"}}%%
    box rgb(8,24,40) Browser
        participant Client as Browser module
    end
    box rgb(8,32,20) Application
        participant App as app
    end
    box rgb(36,28,8) Storage
        participant Store as store
        participant File as Staging file
    end
    Client->>App: send(item): POST /api/uploads + file bytes
    App->>Store: reserve(): allocate upload capacity
    Store-->>App: Reservation or error
    App->>Store: root.OpenFile(stage, flags, 0600)
    Store-->>App: Exclusive staging file handle
    loop Bounded chunks, with size and free-space checks
        App->>File: Write(buffer): up to 64 KiB
    end
    App->>App: Recheck session and call quarantine(file)
    App->>File: Sync(), then Close()
    App->>Store: finalize(stage, name): publish without overwrite
    Store-->>App: Stored filename
    App-->>Client: 201 JSON: name + byte count
    Note over App,Store: Failed or canceled uploads remove staging data<br/>and release reserved capacity.
```

### 2. Inbox: files become metadata and permitted offers

Viewing metadata and downloading contents are separate permissions. An offer is a signed file description bound to the current session, not a filesystem path the client can choose.

```mermaid
sequenceDiagram
    %%{init: {"theme": "dark"}}%%
    box rgb(8,24,40) Browser
        participant Client as Browser module
    end
    box rgb(8,32,20) Application
        participant App as app
    end
    box rgb(36,28,8) Storage
        participant Store as store
    end
    Client->>App: refreshInbox(force): GET /api/inbox
    App->>App: sessionAccess(r): require view permission
    App->>Store: listInbox(ctx): bounded, filtered snapshot
    Store-->>App: Names, sizes, times and file identities
    opt Session has download permission
        App->>App: signOffer(session.offerKey, file)
        Note right of App: HMAC-SHA256 protects the file description.
    end
    App-->>Client: JSON files with offer IDs only when permitted
    Client->>Client: renderInbox(files): update existing rows
```

### 3. Download: a verified offer becomes an attachment stream

The browser initiates this operation only when the user selects Download. A stale, modified or cross-session offer is rejected.

```mermaid
sequenceDiagram
    %%{init: {"theme": "dark"}}%%
    box rgb(8,24,40) Browser
        participant Client as Browser
    end
    box rgb(8,32,20) Application
        participant App as app
    end
    box rgb(36,28,8) Storage
        participant Store as store
    end
    Client->>App: GET /api/downloads/id + session cookie
    App->>App: Require download permission and call verifyOffer(key, id)
    App->>Store: openDownload(offer)
    Note right of Store: Reject symlinks and verify regular-file identity,<br/>size and modification time.
    Store-->>App: Verified file handle or error
    App-->>Client: Attachment headers + expected Content-Length
    loop Up to 64 KiB per buffer
        App->>App: downloadWriter.Write(data): check session and cancellation
        App-->>Client: File bytes
    end
    Note over Client,App: Browser controls saving.<br/>A click is not confirmation of a completed download.
```

## Storage and transfer behavior

- Uploads stream into private staging files, then publish using a no-overwrite hard link. Collisions get unique names.
- Received files are not automatically opened, previewed, extracted or executed; macOS quarantine metadata is applied.
- Listings exclude hidden/unsafe names, symlinks, subfolders and staging files. Names are rendered as text. Timestamps are modification times, not guaranteed received-at times.
- Listings scan at most 1,000 top-level directory entries, including hidden entries. Larger inboxes return an explicit error.
- Download offers use standard HMAC-SHA256 with a per-session key. Another session cannot reuse an offer; tampering fails.
- Download opening uses a pinned directory handle and kernel-level no-follow basename access. Regular-file identity, size and modification time must still match the offer.
- Downloads stream as `application/octet-stream` with `Content-Disposition: attachment`; the browser controls saving. No JavaScript whole-file buffering.
- Downloads do not support ranges/resume. An interrupted download may leave a partial browser-managed file. The app does not claim that clicking Download means it was saved.
- A local process can modify an opened file during transfer; this is not an immutable snapshot service.

Defaults: 1 GiB per upload; 5 GiB committed plus reserved upload capacity per run; two active uploads and two active downloads; a 1 GiB free-space floor; 15 minutes per transfer. The upload timeout option also sets the download deadline.

Upload admission reserves the full per-file limit. Restart resets the per-run budget, not existing disk usage. Actual-byte and free-space checks still apply. Multipart overhead is capped at 64 KiB; HTTP headers at 16 KiB; invitation bodies at 1 KiB with a five-second deadline.

Cancellation and startup cleanup remove only identifiable staging files. Only one receiver can lock an inbox. Use a local filesystem supporting locking, hard links and quarantine attributes. Files are synced before publication; directory/power-loss durability is not promised.

## Testing

```sh
npm run build
npm run typecheck
go test -race ./...
go vet ./...
go build -o bin/filedrop ./src
```

Tests cover session/invitation expiration, permission separation, Host/Origin boundaries, confined storage, collisions, interrupted uploads, limits, listing filters, download offer tampering/replay, changed sources, symlinks, non-regular sources, attachment headers and transfer cancellation. Owner tests cover single-use bootstrap replay and expiry, scoped invitation renewal, unchanged guest permissions, disabled permissions, bounded bodies, local request guards, and QR output/expiry. Pairing tests cover key substitution/replay, single-use enrollment, stale terminal approvals, reductions, durable state, trust reset, fail-closed database errors and publication/revocation ordering.

Browser E2E tests start their own temporary receiver, use a real terminal PTY for confirmation, and test enrollment, upload/native download, reload, server restart, permission reductions/increases, and revocation:

```sh
npx playwright install chromium firefox webkit
npm run test:e2e
```

Build the executable before running E2E. Tests run in Chromium, Firefox and mobile-emulated WebKit; WebKit emulation is not a physical iPhone/Safari test. Test state, reports and traces are not committed.

Optional large-transfer checks compare hashes without buffering whole files:

```sh
FILEDROP_LARGE=1 go test \
  -run 'TestLarge(ConcurrentUploads|Download)$' -v -timeout 5m ./src
```

Optional independent QR round-trip check uses macOS Vision via the Swift command-line tools:

```sh
FILEDROP_QR=1 go test -run TestQRRoundTrip -v ./src
```

Manual acceptance: trusted HTTPS from a second device; upload/download hash comparisons; expired permissions; cancellation; responsive/mobile layout; live refresh; and private Serve/firewall/tailnet exposure.

## Security scope

Authentication and encryption do not make files harmless. Authorized senders can deposit malicious content and consume capacity. Do not place the inbox in executable, web-served, cloud-synced or automation-watched folders.

Tailscale login, access policy, HTTPS configuration and absence of Funnel are external dependencies, not verified by the app. Local malware running as the same user or administrator is outside the protection boundary. Revocation cannot retract already downloaded bytes.

The baseline implementation and the new authenticated download surface received separate bounded read-only security reviews with no verified exploitable findings. That is not proof of security: live attacks, exhaustive dependency review, tailnet policy and filesystem/platform behavior were not independently verified.

Persistent pairing and its post-review refinements also received direct-source security review with no verified reportable findings. Automated tests are evidence for the covered cases, not a guarantee of all browser, crash or network behavior.

Pairing uses fresh, purpose-bound key proofs and authoritative registry status/generation checks during transfers. The terminal confirmation boundary assumes the receiver's local user account is trusted; it is not biometric verification or protection against same-user native malware. Browser nonextractability does not stop same-origin scripts or malicious extensions from using a key. No uploaded content is executed or previewed.

Device-specific validation history is kept in an ignored local Markdown file, not this public document. Git ignore does not erase history or protect a file deliberately force-added; inspect staged changes before publishing.
