"""Fetch and verify the pinned base dependencies for a Windows source build."""
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request


ROOT = pathlib.Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"
LOCK = json.loads((ROOT / "scripts/dependency-lock.json").read_text(encoding="utf-8"))


def git(*args, capture=False):
    result = subprocess.run(["git", *map(str, args)], check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def checkout(stage, repository, revision, sparse=()):
    git("init", "--quiet", stage)
    git("-C", stage, "config", "core.autocrlf", "false")
    git("-C", stage, "remote", "add", "origin", repository)
    if sparse:
        git("-C", stage, "config", "remote.origin.promisor", "true")
        git("-C", stage, "config", "remote.origin.partialclonefilter", "blob:none")
        git("-C", stage, "sparse-checkout", "set", *sparse)
    flags = ["--filter=blob:none"] if sparse else []
    git("-C", stage, "fetch", "--quiet", "--depth=1", *flags, "origin", revision)
    git("-C", stage, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    if re.fullmatch(r"[0-9a-f]{40}", revision):
        if git("-C", stage, "rev-parse", "HEAD", capture=True) != revision:
            raise RuntimeError(f"Incorrect dependency revision: {repository}")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_file(path, expected, normalize=False):
    data = path.read_bytes()
    if normalize:
        data = data.replace(b"\r\n", b"\n")
    if sha(data) != expected:
        raise RuntimeError(f"Dependency hash mismatch: {path}")


def prepare_lua(stage):
    release = "lua-" + LOCK["lua_version"]
    download = stage.parent / (release + ".tar.gz")
    with urllib.request.urlopen(f"https://www.lua.org/ftp/{release}.tar.gz", timeout=60) as source:
        # This archive is under 1 MiB; enforce a bound before hashing it.
        content = source.read(4 * 1024 * 1024 + 1)
    if len(content) > 4 * 1024 * 1024 or sha(content) != LOCK["lua_archive_sha256"]:
        raise RuntimeError("Lua archive failed size/SHA-256 verification")
    download.write_bytes(content)
    stage.mkdir()
    with tarfile.open(download, "r:gz") as archive:
        for member in archive:
            parts = pathlib.PurePosixPath(member.name).parts
            if not parts or parts[0] != release or any(
                    part in {"..", "."} or "\\" in part or ":" in part for part in parts):
                raise RuntimeError("Unexpected Lua archive path")
            if not (member.isdir() or member.isfile()):
                raise RuntimeError("Unexpected Lua archive member type")
            output = stage.joinpath(*parts[1:])
            if member.isdir():
                output.mkdir(parents=True, exist_ok=True)
            else:
                output.parent.mkdir(parents=True, exist_ok=True)
                with archive.extractfile(member) as source, output.open("xb") as target:
                    shutil.copyfileobj(source, target)
    header = (stage / "src/lua.h").read_text(encoding="utf-8")
    notice = re.search(r"^\* (Copyright \(C\).*Lua.org, PUC-Rio\.)\n((?:\*[^\n]*\n)+)", header, re.M)
    if not notice:
        raise RuntimeError("Could not find upstream Lua copyright notice")
    lines = [line[2:] if line.startswith("* ") else "" for line in notice[0].splitlines()
             if line == "*" or line.startswith("* ")]
    (stage / "LICENSE.txt").write_bytes(("\r\n".join(lines) + "\r\n").encode())


def main():
    VENDOR.mkdir(exist_ok=True)
    temp = ROOT / ".tmp"
    temp.mkdir(exist_ok=True)
    projects = {
        "ghidra": ("https://github.com/NationalSecurityAgency/ghidra.git", LOCK["ghidra"]),
        "imgui": ("https://github.com/ocornut/imgui.git", LOCK["imgui"]),
        "zlib": ("https://github.com/madler/zlib.git", LOCK["zlib"]),
        "zydis": ("https://github.com/zyantific/zydis.git", LOCK["zydis"]),
        "capstone": ("https://github.com/capstone-engine/capstone.git", "refs/tags/" + LOCK["capstone_tag"]),
        "json": ("https://github.com/nlohmann/json.git", "refs/tags/" + LOCK["json"]),
    }
    for name in (*projects, "lua"):
        destination = VENDOR / name
        if destination.exists():
            print(f"Checking existing {name}", flush=True)
        else:
            print(f"Preparing {name}", flush=True)
            with tempfile.TemporaryDirectory(prefix="source-dependency-", dir=temp) as folder:
                stage = pathlib.Path(folder) / "checkout"
                if name == "lua":
                    prepare_lua(stage)
                else:
                    sparse = ("Ghidra/Features/Decompiler/src/decompile/cpp",) if name == "ghidra" else ()
                    checkout(stage, *projects[name], sparse)
                    if name == "ghidra":
                        for row in LOCK["ghidra_modified_files"]:
                            verify_file(stage / row["path"], row["upstream_sha256_lf"], normalize=True)
                        git("-C", stage, "apply", ROOT / "scripts/patches/ghidra-native.patch")
                    elif name == "zydis":
                        git("-C", stage, "submodule", "update", "--init", "--depth=1", "dependencies/zycore")
                    elif name == "json":
                        stage_json = stage.parent / "json"
                        stage_json.mkdir()
                        shutil.copyfile(stage / "single_include/nlohmann/json.hpp", stage_json / "json.hpp")
                        shutil.copyfile(stage / "LICENSE.MIT", stage_json / "LICENSE.MIT")
                        stage = stage_json
                verify(name, stage, projects)
                stage.rename(destination)
        verify(name, destination, projects)
    print("Pinned base dependencies are ready.")


def verify(name, path, projects):
    if name in ("ghidra", "imgui", "zlib", "zydis"):
        if not (path / ".git").exists() or git("-C", path, "rev-parse", "HEAD", capture=True) != projects[name][1]:
            raise RuntimeError(f"Incorrect existing Git checkout at {path}; preserve it before replacing")
    if name == "ghidra":
        for row in LOCK["ghidra_modified_files"]:
            verify_file(path / row["path"], row["modified_sha256_lf"], normalize=True)
    if name == "zydis":
        if git("-C", path / "dependencies/zycore", "rev-parse", "HEAD", capture=True) != LOCK["zycore"]:
            raise RuntimeError("Incorrect Zycore revision")
    prefix = f"vendor/{name}/"
    for file, expected in LOCK["local_file_sha256"].items():
        if file.startswith(prefix):
            verify_file(path / file.removeprefix(prefix), expected)


if __name__ == "__main__":
    main()
