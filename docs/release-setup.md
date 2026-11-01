# File Drop macOS preview

This archive contains a macOS command-line receiver. Go and Node.js are **not required** to run it. Sending devices use a browser.

## Before starting

- Choose `darwin-arm64` for Apple Silicon or `darwin-amd64` for Intel.
- macOS 15 is the tested baseline. Older versions are not certified by this preview.
- The binary is **ad-hoc signed only**, not Developer ID signed or notarized. The signature does not establish a trusted publisher identity.
- macOS may warn or block execution of downloaded previews. Do not disable Gatekeeper or broadly remove quarantine protections. If your policy requires notarization, wait for a signed release or build from the reviewed source.
- Install Tailscale on the receiver and clients and authorize them in the same tailnet. No cloud file storage is used, but Tailscale coordination and encrypted relays may use external services.

## Verify and extract

Download the archive for your Mac and `SHA256SUMS.txt` from the same release. In Terminal, go to the download directory and check the matching line:

```sh
grep 'darwin-arm64.tar.gz$' SHA256SUMS.txt | shasum -a 256 -c -
```

Use `darwin-amd64.tar.gz$` instead for Intel. Continue only if the result is `OK`.

Checksums detect corruption; they are not an independent publisher signature. Obtain them from the official release page.

Extract the archive, open a terminal in its extracted folder, then run:

```sh
./bin/filedrop -version
```

The version/platform should match the archive and `BUILDINFO.json`.

## Start private sharing

In one terminal:

```sh
tailscale serve status
tailscale serve --https=443 http://127.0.0.1:8443
```

Do not replace unrelated Serve configuration. Follow HTTPS prompts with optional Funnel access unchecked. Keep this terminal running.

If the macOS app did not install `tailscale` on your PATH, use `/Applications/Tailscale.app/Contents/MacOS/Tailscale` in its place.

In a second terminal, replace the example URL with the exact HTTPS origin printed by Serve:

```sh
./bin/filedrop \
  -tailscale-serve \
  -share-inbox \
  -allow-downloads \
  -listen 127.0.0.1:8443 \
  -public-url https://receiver.example-tailnet.ts.net \
  -owner-listen 127.0.0.1:18445 \
  -inbox "$HOME/FileDropInbox"
```

Open the **owner link** on the receiving Mac. Create a temporary invitation and copy it or scan its QR on a Tailscale-connected client. Select files and Upload; wait for **Saved**. Download permission covers the visible inbox.

Use **Serve, never Funnel**. Keep the receiver awake; restrict access with your tailnet policy. Stop File Drop with Ctrl+C when finished. Saved files remain on disk.

## Optional remembered browsers

Initialize private state once:

```sh
./bin/filedrop init -state-dir "$HOME/Library/Application Support/FileDrop"
```

Add `-state-dir "$HOME/Library/Application Support/FileDrop"` to the receiver command.

Select **Remember browser** on the owner page. The client requests pairing; compare fingerprints and run the pending terminal confirmation command from this extracted folder. The executable path remains `./bin/filedrop`.

Pairing lasts until revoked; sessions last 30 minutes. New approvals and permission increases require terminal confirmation. Clearing browser site data requires re-pairing.

## Contents and licenses

- `bin/filedrop`: receiver executable
- `BUILDINFO.json`: version, public source revision, platform, toolchain, and linked modules
- `LICENSE`: File Drop's MIT license
- `THIRD_PARTY_NOTICES.md` and `licenses/`: dependency, Go, and font notices

Do not open or execute untrusted uploaded files. This preview has no automatic file opening, syncing, previews, or remote deletion. See the repository README and technical reference for limits and recovery.
