# Packaging a preview release

Run from a clean repository checkout on macOS with Go, Node/npm, Python 3, and `codesign`. The initial preview is ad-hoc signed, not Developer ID signed or notarized.

1. Install dependencies with `npm ci`.
2. Run the normal Go/frontend/E2E checks.
3. Commit the release source and create its version tag.
4. Build from that exact clean tag:

```sh
python3 scripts/package_release.py --version v0.1.0
```

Outputs in `dist/v0.1.0/`:

- `file-drop-v0.1.0-darwin-arm64.tar.gz`
- `file-drop-v0.1.0-darwin-amd64.tar.gz`
- `SHA256SUMS.txt`

The packager refuses dirty source, a tag pointing elsewhere, an existing output directory, unresolved/local module replacements, missing licenses, incorrect binary provenance, or invalid signing checks. Use `--output dist/another-validation-directory` for an additional build; it does not overwrite a release.

Each archive includes `bin/filedrop`, the app license, concise setup instructions, public build metadata and dependency/Go/font notices. Only those explicitly assembled files enter the archive; no inbox, state, environment snapshot or logs are copied. Module notices are derived from the binary's actual linked dependencies, not every test/build dependency in the module graph.

Archives normalize ownership and timestamps. Checksums are calculated after ad-hoc signing and packaging. Repeatability is tested for archive creation; byte-identical binaries still depend on the toolchain and signing tools.

Verify checksums, archive contents, signatures and the native binary before publication. Run E2E against an extracted binary:

```sh
FILEDROP_BINARY=/absolute/path/to/extracted/bin/filedrop npm run test:e2e
```

Cross-compiled Intel output is not proof of native Intel compatibility. Document which architectures were actually executed.

Publish only after source CI and artifact checks pass. Upload both archives and the checksum file to an explicitly labeled GitHub prerelease. Never describe ad-hoc signing as verified publisher identity or notarization.

For broader distribution, add Developer ID signing and Apple notarization using protected local/CI credentials. Do not commit signing certificates, private keys, Apple credentials or notary tokens.
