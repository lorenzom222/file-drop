#!/usr/bin/env python3
"""Build allowlisted, ad-hoc-signed macOS preview archives from a clean tag."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LICENSE_PREFIXES = ("LICENSE", "COPYING", "COPYRIGHT", "NOTICE", "PATENTS", "GO-LICENSE")


def run(*args, env=None):
    return subprocess.check_output(args, cwd=ROOT, env=env, text=True).strip()


def json_documents(text):
    decoder = json.JSONDecoder()
    remaining = text.lstrip()
    result = []
    while remaining:
        value, end = decoder.raw_decode(remaining)
        result.append(value)
        remaining = remaining[end:].lstrip()
    return result


def license_files(directory):
    return sorted(
        file for file in directory.iterdir()
        if file.is_file() and file.name.upper().startswith(LICENSE_PREFIXES)
    )


def copy_notices(directory, output, label):
    files = license_files(directory)
    if not any("LICENSE" in file.name.upper() or "COPYING" in file.name.upper() for file in files):
        raise RuntimeError(f"No distribution license found for {label}")
    output.mkdir(parents=True, exist_ok=True)
    for file in files:
        shutil.copyfile(file, output / file.name)
    return [file.name for file in files]


def notices(bundle, build, modules, go_root):
    lines = [
        "# Third-party notices",
        "",
        "These components are linked into or embedded in this receiver. "
        "Original license, copyright, patent and notice files are included below. "
        "The application's MIT license does not relicense dependencies.",
        "",
    ]
    for index, dependency in enumerate(build["Deps"]):
        name, version = dependency["Path"], dependency["Version"]
        module = modules.get(name)
        if dependency.get("Replace") or not module or module.get("Replace") or module.get("Version") != version:
            raise RuntimeError(f"Unresolved or replaced release dependency: {name}")
        directory = Path(module["Dir"])
        destination = bundle / "licenses" / f"module-{index:02d}"
        files = copy_notices(directory, destination, name)
        lines += [f"## {name} {version}", ""] + [
            f"- [{file}](licenses/{destination.name}/{file})" for file in files
        ] + [""]
    go_license = next(
        (file for file in [go_root / "LICENSE", go_root.parent / "LICENSE"] if file.is_file()),
        None,
    )
    if go_license is None:
        raise RuntimeError("Go distribution license is missing")
    destination = bundle / "licenses" / "go"
    destination.mkdir(parents=True)
    shutil.copyfile(go_license, destination / "LICENSE")
    lines += [f"## Go standard library ({build['GoVersion']})", "", "- [LICENSE](licenses/go/LICENSE)"]
    if (go_root / "PATENTS").is_file():
        shutil.copyfile(go_root / "PATENTS", destination / "PATENTS")
        lines += ["- [PATENTS](licenses/go/PATENTS)"]
    # Preserve notices of Go's vendored standard-library components as well.
    vendor = go_root / "src" / "vendor"
    if vendor.is_dir():
        for file in sorted(vendor.rglob("*")):
            if file.is_file() and file.name.upper().startswith(LICENSE_PREFIXES):
                relative = file.relative_to(vendor)
                target = bundle / "licenses" / "go-vendor" / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(file, target)
                lines.append(f"- [{relative.as_posix()}](licenses/go-vendor/{relative.as_posix()})")
    font = bundle / "licenses" / "jetbrains-mono"
    font.mkdir(parents=True)
    shutil.copyfile(ROOT / "src/ui/fonts/OFL.txt", font / "OFL.txt")
    lines += ["", "## JetBrains Mono", "", "- [SIL Open Font License 1.1](licenses/jetbrains-mono/OFL.txt)", ""]
    (bundle / "THIRD_PARTY_NOTICES.md").write_text("\n".join(lines), encoding="utf-8")


def archive(bundle, destination, epoch):
    with destination.open("wb") as stream:
        with gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as tar:
                for file in [bundle, *sorted(bundle.rglob("*"))]:
                    relative = file.relative_to(bundle.parent).as_posix()
                    if file.is_symlink():
                        raise RuntimeError("Release bundles must not contain symlinks")
                    info = tarfile.TarInfo(relative)
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = epoch
                    if file.is_dir():
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        tar.addfile(info)
                    else:
                        info.mode = 0o755 if file == bundle / "bin/filedrop" else 0o644
                        info.size = file.stat().st_size
                        with file.open("rb") as contents:
                            tar.addfile(info, contents)


def package(version, output):
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?", version):
        raise RuntimeError("Use a release tag such as v0.1.0")
    if sys.platform != "darwin":
        raise RuntimeError("Packaging requires macOS codesign")
    if run("git", "status", "--porcelain"):
        raise RuntimeError("Release packaging requires a clean worktree")
    revision = run("git", "rev-parse", "HEAD")
    if run("git", "rev-parse", f"{version}^{{commit}}") != revision:
        raise RuntimeError("Release tag must resolve to the current commit")
    if output.exists():
        raise RuntimeError(f"Output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    run("npm", "run", "typecheck")
    run("npm", "run", "build")
    modules = {item["Path"]: item for item in json_documents(run("go", "list", "-m", "-json", "all"))}
    go_root = Path(run("go", "env", "GOROOT"))
    epoch = int(run("git", "show", "-s", "--format=%ct", "HEAD"))
    with tempfile.TemporaryDirectory(prefix=".filedrop-release-", dir=output.parent) as temporary:
        stage = Path(temporary)
        archives = []
        for architecture in ["arm64", "amd64"]:
            name = f"file-drop-{version}-darwin-{architecture}"
            bundle = stage / name
            (bundle / "bin").mkdir(parents=True)
            binary = bundle / "bin/filedrop"
            env = dict(os.environ, GOOS="darwin", GOARCH=architecture, CGO_ENABLED="0")
            run("go", "build", "-trimpath", "-buildvcs=true",
                "-ldflags", f"-s -w -X main.releaseVersion={version} -X main.releaseRevision={revision[:12]}",
                "-o", str(binary), "./src", env=env)
            run("codesign", "--force", "--sign", "-", "--timestamp=none", str(binary))
            run("codesign", "--verify", "--strict", "--verbose=2", str(binary))
            build = json.loads(run("go", "version", "-m", "-json", str(binary)))
            settings = {item["Key"]: item["Value"] for item in build["Settings"]}
            if settings.get("GOOS") != "darwin" or settings.get("GOARCH") != architecture or settings.get("CGO_ENABLED") != "0" or settings.get("vcs.revision") != revision or settings.get("vcs.modified") != "false":
                raise RuntimeError("Binary platform or provenance does not match the release")
            shutil.copyfile(ROOT / "LICENSE", bundle / "LICENSE")
            shutil.copyfile(ROOT / "docs/release-setup.md", bundle / "SETUP.md")
            notices(bundle, build, modules, go_root)
            metadata = {
                "version": version, "revision": revision, "platform": f"darwin/{architecture}",
                "go_version": build["GoVersion"],
                "signing": "ad-hoc only; not Developer ID signed or notarized",
                "modules": [{key: item[key] for key in ["Path", "Version", "Sum"]} for item in build["Deps"]],
            }
            (bundle / "BUILDINFO.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
            destination = stage / (name + ".tar.gz")
            archive(bundle, destination, epoch)
            archives.append(destination)
        ready = stage / "ready"
        ready.mkdir()
        checksums = []
        for file in archives:
            digest = hashlib.sha256(file.read_bytes()).hexdigest()
            checksums.append(f"{digest}  {file.name}\n")
            shutil.move(file, ready / file.name)
        (ready / "SHA256SUMS.txt").write_text("".join(checksums), encoding="ascii")
        ready.rename(output)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    output = args.output or ROOT / "dist" / args.version
    try:
        print(package(args.version, output.resolve()))
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as error:
        parser.exit(1, f"Release packaging failed: {error}\n")


if __name__ == "__main__":
    main()
