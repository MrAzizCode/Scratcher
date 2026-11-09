"""Read-only, code-only acquisition from an explicitly selected existing PID.

This tool never launches a target, attaches a debugger, changes page protection,
enables privileges, injects code, or retries inaccessible pages by bypassing them.
Only original executable/validated entry/Guard-CF candidate ranges are exported.
Headers and bounded build-identification records are read for identity checks.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import time
import uuid

ROOT = Path("D:/Scratcher").resolve()
MEM_COMMIT, MEM_IMAGE, PAGE_GUARD, PAGE_NOACCESS = 0x1000, 0x1000000, 0x100, 1
READABLE = {2, 4, 8, 0x20, 0x40, 0x80}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def number(value):
    return int(value, 0) if isinstance(value, str) else int(value)


def output_path(value):
    path = Path(value).resolve()
    if not path.is_relative_to(ROOT) or path == ROOT:
        raise ValueError("Output must be inside D:/Scratcher in a dedicated directory")
    return path


class PE:
    def __init__(self, data):
        self.data = data
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("Not a PE image")
        off = self.u32(0x3C)
        if off > 16 * 1024 * 1024 or self.slice(off, 24)[:4] != b"PE\0\0":
            raise ValueError("Invalid PE header")
        self.pe_offset = off
        self.machine, count = self.unpack("<HH", off + 4)
        self.timestamp = self.u32(off + 8)
        opt_size = self.unpack("<H", off + 20)[0]
        self.opt = off + 24
        magic = self.unpack("<H", self.opt)[0]
        self.bits = {0x10B: 32, 0x20B: 64}.get(magic)
        if not self.bits or count > 4096 or opt_size < (112 if self.bits == 64 else 96):
            raise ValueError("Invalid optional header or section count")
        self.slice(self.opt, opt_size)
        self.entry = self.u32(self.opt + 16)
        self.base = self.unpack("<Q" if self.bits == 64 else "<I", self.opt + (24 if self.bits == 64 else 28))[0]
        self.image_size = self.u32(self.opt + 56)
        self.headers_size = self.u32(self.opt + 60)
        self.checksum = self.u32(self.opt + 64)
        directory_off = self.opt + (112 if self.bits == 64 else 96)
        directory_count = self.u32(directory_off - 4)
        self.directories = []
        for n in range(min(16, directory_count)):
            if directory_off + 8 * (n + 1) > self.opt + opt_size:
                raise ValueError("Truncated PE directories")
            self.directories.append(self.unpack("<II", directory_off + n * 8))
        self.sections = []
        for n in range(count):
            at = self.opt + opt_size + n * 40
            row = self.slice(at, 40)
            virtual, rva, raw_size, raw_offset = struct.unpack_from("<IIII", row, 8)
            if rva > self.image_size or max(virtual, raw_size) > self.image_size - rva:
                raise ValueError("Section extends beyond SizeOfImage")
            self.sections.append({"name": row[:8].split(b"\0")[0].decode("ascii", "replace"),
                                  "rva": rva, "virtual_size": virtual, "raw_size": raw_size,
                                  "raw_offset": raw_offset, "flags": struct.unpack_from("<I", row, 36)[0]})

    def slice(self, off, size):
        if off < 0 or size < 0 or off > len(self.data) or size > len(self.data) - off:
            raise ValueError("Truncated PE bytes")
        return self.data[off:off + size]

    def unpack(self, fmt, off):
        return struct.unpack(fmt, self.slice(off, struct.calcsize(fmt)))

    def u32(self, off):
        return self.unpack("<I", off)[0]

    def directory(self, index):
        return self.directories[index] if index < len(self.directories) else (0, 0)

    def section(self, rva):
        return next((s for s in self.sections if s["rva"] <= rva < s["rva"] + max(s["virtual_size"], s["raw_size"])), None)

    def rva_bytes(self, rva, size):
        if rva < self.headers_size and size <= self.headers_size - rva:
            return self.slice(rva, size)
        s = self.section(rva)
        if not s or rva - s["rva"] > s["raw_size"] or size > s["raw_size"] - (rva - s["rva"]):
            raise ValueError("Metadata is not completely file backed")
        return self.slice(s["raw_offset"] + rva - s["rva"], size)

    def identity(self):
        return {"machine": self.machine, "bits": self.bits, "timestamp": self.timestamp,
                "size_of_image": self.image_size, "optional_header_checksum": self.checksum,
                "entry_rva": self.entry}


def codeview(pe, read_rva):
    rva, size = pe.directory(6)
    if not rva or not size:
        return []
    if size > 1024 * 1024 or size % 28:
        raise ValueError("Malformed debug directory")
    directory = read_rva(rva, size)
    records = []
    for at in range(0, size, 28):
        typ, length, payload_rva = struct.unpack_from("<III", directory, at + 12)
        if typ != 2:
            continue
        if not payload_rva or length < 24 or length > 4096:
            raise ValueError("Invalid bounded CodeView record")
        payload = read_rva(payload_rva, length)
        if payload[:4] == b"RSDS":
            records.append({"guid": str(uuid.UUID(bytes_le=payload[4:20])), "age": struct.unpack_from("<I", payload, 20)[0]})
        else:
            records.append({"format": payload[:4].hex(), "record_sha256": sha(payload)})
    return records


def version_records(pe, read_rva):
    root, size = pe.directory(2)
    if not root or not size:
        return []
    if size > 128 * 1024 * 1024:
        raise ValueError("Resource directory exceeds identity bounds")
    def relative(offset, count):
        if offset > size or count > size - offset:
            raise ValueError("Resource identity record outside directory")
        return read_rva(root + offset, count)
    def entries(offset):
        header = relative(offset, 16)
        count = sum(struct.unpack_from("<HH", header, 12))
        if count > 4096:
            raise ValueError("Resource identity directory too large")
        data = relative(offset + 16, count * 8)
        return [struct.unpack_from("<II", data, at) for at in range(0, len(data), 8)]
    types = [child & 0x7FFFFFFF for name, child in entries(0) if name == 16 and child & 0x80000000]
    result = []
    for offset in types:
        for resource_id, child in entries(offset):
            if not child & 0x80000000:
                raise ValueError("Malformed version resource directory")
            for language, leaf in entries(child & 0x7FFFFFFF):
                if leaf & 0x80000000:
                    raise ValueError("Unexpected nested version resource")
                payload_rva, length = struct.unpack_from("<II", relative(leaf, 16))
                if not length or length > 1024 * 1024:
                    raise ValueError("Version resource exceeds identity bound")
                payload = read_rva(payload_rva, length)
                marker = payload.find(b"\xbd\x04\xef\xfe")
                fixed = None
                if marker >= 0 and marker + 52 <= len(payload):
                    values = struct.unpack_from("<13I", payload, marker)
                    fixed = {"file_version": [values[2] >> 16, values[2] & 65535, values[3] >> 16, values[3] & 65535]}
                result.append({"resource_id": resource_id, "language": language, "size": length,
                               "resource_sha256": sha(payload), "fixed_file_info": fixed})
    return result


def merge_ranges(ranges):
    result = []
    for begin, end in sorted(ranges):
        if begin >= end:
            continue
        if result and begin <= result[-1][1]:
            result[-1][1] = max(result[-1][1], end)
        else:
            result.append([begin, end])
    return result


def candidate_ranges(pe):
    reasons = {}
    def include(rva, reason):
        s = pe.section(rva)
        if s and rva - s["rva"] < s["raw_size"]:
            reasons.setdefault(s["rva"], set()).add(reason)
    for s in pe.sections:
        if s["flags"] & 0x20000000:
            include(s["rva"], "original_executable_section")
    if pe.entry:
        include(pe.entry, "original_entry_point")
    rva, directory_size = pe.directory(10)
    guard_count = 0
    if rva and directory_size:
        required = 148 if pe.bits == 64 else 92
        declared = struct.unpack("<I", pe.rva_bytes(rva, 4))[0]
        if min(declared, directory_size) >= required:
            config = pe.rva_bytes(rva, required)
            ptr_offset, count_offset, flags_offset = (128, 136, 144) if pe.bits == 64 else (80, 84, 88)
            fmt = "<Q" if pe.bits == 64 else "<I"
            table = struct.unpack_from(fmt, config, ptr_offset)[0]
            count = struct.unpack_from(fmt, config, count_offset)[0]
            flags = struct.unpack_from("<I", config, flags_offset)[0]
            stride = 4 + (flags >> 28)
            if count > 1_000_000:
                raise ValueError("Guard CF table exceeds bounded metadata limit")
            if table and count and flags & 0x400:  # IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT
                if table < pe.base or table - pe.base > pe.image_size:
                    raise ValueError("Invalid Guard CF table address")
                table_bytes = pe.rva_bytes(table - pe.base, count * stride)
                for at in range(0, len(table_bytes), stride):
                    target = struct.unpack_from("<I", table_bytes, at)[0]
                    if stride > 4 and table_bytes[at + 4] & 1:
                        continue
                    s = pe.section(target)
                    if not s or target - s["rva"] >= s["raw_size"]:
                        raise ValueError("Invalid file-backed Guard CF target")
                    include(target, "validated_guard_cf_entry")
                    guard_count += 1
    details = []
    for s in pe.sections:
        if s["rva"] in reasons and s["raw_size"]:
            pe.rva_bytes(s["rva"], s["raw_size"])
            details.append({"rva_start": s["rva"], "rva_end": s["rva"] + s["raw_size"],
                            "section": s["name"], "reasons": sorted(reasons[s["rva"]])})
    return merge_ranges((r["rva_start"], r["rva_end"]) for r in details), details, guard_count


class MODULEENTRY32W(C.Structure):
    _fields_ = [("dwSize", W.DWORD), ("th32ModuleID", W.DWORD), ("th32ProcessID", W.DWORD),
                ("GlblcntUsage", W.DWORD), ("ProccntUsage", W.DWORD), ("modBaseAddr", C.c_void_p),
                ("modBaseSize", W.DWORD), ("hModule", C.c_void_p), ("szModule", W.WCHAR * 256),
                ("szExePath", W.WCHAR * 260)]


class MEMORY_BASIC_INFORMATION(C.Structure):
    _fields_ = [("BaseAddress", C.c_void_p), ("AllocationBase", C.c_void_p), ("AllocationProtect", W.DWORD),
                ("PartitionId", W.WORD), ("RegionSize", C.c_size_t), ("State", W.DWORD),
                ("Protect", W.DWORD), ("Type", W.DWORD)]


class Reader:
    def __init__(self, pid, module):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise ValueError("Requires 64-bit Python on Windows")
        self.k = C.WinDLL("kernel32", use_last_error=True)
        signatures = {
            "OpenProcess": ([W.DWORD, W.BOOL, W.DWORD], W.HANDLE),
            "CloseHandle": ([W.HANDLE], W.BOOL),
            "CreateToolhelp32Snapshot": ([W.DWORD, W.DWORD], W.HANDLE),
            "Module32FirstW": ([W.HANDLE, C.POINTER(MODULEENTRY32W)], W.BOOL),
            "Module32NextW": ([W.HANDLE, C.POINTER(MODULEENTRY32W)], W.BOOL),
            "VirtualQueryEx": ([W.HANDLE, C.c_void_p, C.POINTER(MEMORY_BASIC_INFORMATION), C.c_size_t], C.c_size_t),
            "ReadProcessMemory": ([W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)], W.BOOL),
        }
        for name, (args, result) in signatures.items():
            api = getattr(self.k, name)
            api.argtypes, api.restype = args, result
        self.handle = self.k.OpenProcess(0x400 | 0x10, False, pid)  # QUERY_INFORMATION | VM_READ only
        if not self.handle:
            raise OSError(C.get_last_error(), "OpenProcess read-only failed")
        try:
            snapshot = self.k.CreateToolhelp32Snapshot(8 | 16, pid)
            if snapshot == C.c_void_p(-1).value:
                raise OSError(C.get_last_error(), "Module snapshot failed")
            try:
                entry = MODULEENTRY32W()
                entry.dwSize = C.sizeof(entry)
                ok = self.k.Module32FirstW(snapshot, C.byref(entry))
                found = []
                while ok:
                    if entry.szModule.casefold() == module.casefold():
                        found.append((entry.modBaseAddr, entry.modBaseSize, entry.szExePath))
                    ok = self.k.Module32NextW(snapshot, C.byref(entry))
                if len(found) != 1:
                    raise ValueError("Expected exactly one explicitly named loaded module")
                self.base, self.size, self.path = found[0]
            finally:
                self.k.CloseHandle(snapshot)
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None

    def query(self, address):
        info = MEMORY_BASIC_INFORMATION()
        if self.k.VirtualQueryEx(self.handle, address, C.byref(info), C.sizeof(info)) != C.sizeof(info):
            return None, C.get_last_error()
        return info, 0

    def read(self, address, length):
        buf = (C.c_ubyte * length)()
        copied = C.c_size_t()
        C.set_last_error(0)
        ok = self.k.ReadProcessMemory(self.handle, address, buf, length, C.byref(copied))
        return bytes(buf[:copied.value]), bool(ok), 0 if ok else C.get_last_error()

    def exact(self, rva, length):
        if rva < 0 or length < 0 or rva > self.size or length > self.size - rva:
            raise ValueError("Identity record is outside selected module")
        remaining, cursor = length, self.base + rva
        chunks = []
        while remaining:
            info, error = self.query(cursor)
            if not info or not readable(info, self.base):
                raise OSError(error or 998, "Build identity page unavailable; capture refused")
            count = min(remaining, info.BaseAddress + info.RegionSize - cursor, 1024 * 1024)
            data, ok, error = self.read(cursor, count)
            if not ok or len(data) != count:
                raise OSError(error or 299, "Incomplete identity read; capture refused")
            chunks.append(data)
            cursor += count
            remaining -= count
        return b"".join(chunks)


def readable(info, module_base):
    return (info.State == MEM_COMMIT and info.Type == MEM_IMAGE and info.AllocationBase == module_base
            and not info.Protect & PAGE_GUARD and not info.Protect & PAGE_NOACCESS
            and info.Protect & 0xFF in READABLE)


def select_ranges(pe, original_hash, provenance):
    ranges, details, guard_count = candidate_ranges(pe)
    if provenance:
        doc = json.loads(Path(provenance).read_text(encoding="utf-8"))
        if doc.get("original_sha256", "").casefold() != original_hash:
            raise ValueError("Provenance must match original_sha256")
        supplied = merge_ranges((number(r["rva_start"]), number(r["rva_end"])) for r in doc["candidate_ranges"])
        for begin, end in supplied:
            if not any(begin >= a and end <= b for a, b in ranges):
                raise ValueError("Provenance cannot expand beyond independently validated candidate code")
        ranges = supplied
    return ranges, details, guard_count


def capture(pid, original, module, out, provenance=None):
    original = Path(original).resolve(strict=True)
    out = output_path(out)
    if out.exists() and any(out.iterdir()):
        raise ValueError("Output directory must be empty; existing captures are never overwritten")
    image = original.read_bytes()
    original_hash = sha(image)
    pe = PE(image)
    ranges, details, guard_count = select_ranges(pe, original_hash, provenance)
    manifest = {"schema_version": 1, "pid": pid, "module_name": module,
                "original_path": str(original), "original_sha256": original_hash,
                "source_pe_sha256": original_hash,
                "original_identity": pe.identity(), "candidate_ranges": ranges,
                "candidate_range_details": details, "validated_guard_cf_entries": guard_count,
                "requested_code_bytes": sum(b - a for a, b in ranges), "captured_ranges": [], "missing_ranges": [],
                "byte_source": "already_running_process_read_only", "semantic_analysis_complete": False,
                "capture_is_atomic": False, "process_suspended": False,
                "protection_changes": 0, "injection": False, "debugger_attach": False,
                "non_code_bytes_exported": 0, "capture_started_unix": time.time()}
    reader = Reader(pid, module)
    try:
        manifest["module_base"] = reader.base
        manifest["module_path"] = reader.path
        if reader.size != pe.image_size or file_sha(Path(reader.path)) != original_hash:
            raise ValueError("Loaded module file SHA256 or SizeOfImage differs from explicit original")
        header_prefix = reader.exact(0, 64)
        if header_prefix[:2] != b"MZ":
            raise ValueError("Loaded module has invalid DOS header")
        loaded_pe_offset = struct.unpack_from("<I", header_prefix, 0x3C)[0]
        if loaded_pe_offset != pe.pe_offset or pe.headers_size > 16 * 1024 * 1024:
            raise ValueError("Loaded header layout differs or exceeds bounded read")
        loaded = PE(reader.exact(0, pe.headers_size))
        if loaded.identity() != pe.identity() or loaded.sections != pe.sections or loaded.directories != pe.directories:
            raise ValueError("Loaded PE identity/section/directory metadata differs from original")
        disk_guid, memory_guid = codeview(pe, pe.rva_bytes), codeview(loaded, reader.exact)
        disk_version, memory_version = version_records(pe, pe.rva_bytes), version_records(loaded, reader.exact)
        if disk_guid != memory_guid or disk_version != memory_version:
            raise ValueError("Loaded CodeView GUID/version resources differ from original")
        manifest["loaded_identity"] = loaded.identity()
        manifest["codeview_records"] = disk_guid
        manifest["version_records"] = disk_version
        manifest["module_identity"] = dict(loaded.identity(), codeview_records=disk_guid, version_records=disk_version)
        manifest["identity_verified_before_capture"] = True
        manifest["identity_limitations"] = [] if disk_guid and disk_version else ["Some optional GUID/version records are absent; exact backing-file SHA and loaded header metadata still matched."]
        out.mkdir(parents=True, exist_ok=True)
        for begin, end in ranges:
            cursor = reader.base + begin
            while cursor < reader.base + end:
                info, error = reader.query(cursor)
                if not info:
                    length = min(4096 - (cursor & 4095), reader.base + end - cursor)
                else:
                    length = min(info.BaseAddress + info.RegionSize - cursor, reader.base + end - cursor, 1024 * 1024)
                if length <= 0:
                    raise ValueError("Invalid memory region returned by Windows")
                row = {"rva_start": cursor - reader.base, "rva_end": cursor - reader.base + length,
                       "protection": info.Protect if info else None, "state": info.State if info else None,
                       "type": info.Type if info else None}
                if not info or not readable(info, reader.base):
                    row.update({"reason": "query_failed" if not info else "not_readable_committed_image_or_guard_page",
                                "win32_error": error})
                    manifest["missing_ranges"].append(row)
                else:
                    data, ok, error = reader.read(cursor, length)
                    if data:
                        name = f"code-{cursor - reader.base:08x}-{cursor - reader.base + len(data):08x}.bin"
                        path = out / name
                        path.write_bytes(data)
                        captured = dict(row, rva_end=cursor - reader.base + len(data), file=name,
                                        sha256=sha(data), bytes=len(data), read_call_succeeded=ok)
                        manifest["captured_ranges"].append(captured)
                    if len(data) < length:
                        manifest["missing_ranges"].append(dict(row, rva_start=cursor - reader.base + len(data),
                                                              reason="read_failed_or_partial", win32_error=error))
                cursor += length
        # Recheck immutable identity at completion. This is not a process-wide snapshot.
        if reader.exact(0, pe.headers_size) != loaded.data:
            raise ValueError("Loaded header changed during acquisition")
        manifest["original_sha256_after"] = file_sha(original)
        if manifest["original_sha256_after"] != original_hash:
            raise ValueError("Original file changed during acquisition")
        manifest["source_file_unchanged"] = True
        manifest["loaded_module_file_sha256_after"] = file_sha(Path(reader.path))
        if manifest["loaded_module_file_sha256_after"] != original_hash:
            raise ValueError("Loaded module backing file changed during acquisition")
        manifest["captured_code_bytes"] = sum(r["bytes"] for r in manifest["captured_ranges"])
        manifest["missing_code_bytes"] = sum(r["rva_end"] - r["rva_start"] for r in manifest["missing_ranges"])
        manifest["capture_coverage_percent"] = (100.0 * manifest["captured_code_bytes"] / manifest["requested_code_bytes"]
                                                  if manifest["requested_code_bytes"] else 0.0)
        manifest["capture_finished_unix"] = time.time()
        manifest["complete_requested_code_capture"] = manifest["missing_code_bytes"] == 0
        manifest["ranges"] = [{"start_rva": r["rva_start"], "end_rva": r["rva_end"],
                               "output_file": r["file"], "bytes": r["bytes"], "sha256": r["sha256"]}
                              for r in manifest["captured_ranges"]]
        manifest["scope"] = {"candidate_ranges": ranges, "requested_code_bytes": manifest["requested_code_bytes"],
                             "policy": "Original executable/entry/validated Guard CF file-backed section candidates; optional provenance may only narrow this scope."}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return manifest
    except BaseException as ex:
        if manifest.get("identity_verified_before_capture"):
            manifest["capture_failed"] = str(ex)
            out.mkdir(parents=True, exist_ok=True)
            (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        raise
    finally:
        reader.close()


def self_test(report):
    # Uses only this script's own already-running Python process.
    pid = os.getpid()
    original = Path(sys.executable).resolve()
    out = ROOT / ".tmp" / f"capture-code-selftest-{pid}-{time.time_ns()}"
    pe = PE(original.read_bytes())
    ranges, details, _ = candidate_ranges(pe)
    text = next(s for s in pe.sections if s["name"] == ".text")
    provenance = out.parent / f"capture-provenance-selftest-{pid}.json"
    provenance.write_text(json.dumps({"original_sha256": file_sha(original), "candidate_ranges": [
        {"rva_start": text["rva"], "rva_end": text["rva"] + text["raw_size"]}]}), encoding="utf-8")
    result = capture(pid, original, original.name, out, provenance)
    assertions = {"own_process_only": result["pid"] == pid, "identity_verified": result["identity_verified_before_capture"],
                  "text_only": all(text["rva"] <= r["rva_start"] < r["rva_end"] <= text["rva"] + text["raw_size"] for r in result["captured_ranges"]),
                  "exact_accounting": result["captured_code_bytes"] + result["missing_code_bytes"] == result["requested_code_bytes"],
                  "bytes_captured": result["captured_code_bytes"] > 0, "source_unchanged": result["source_file_unchanged"],
                  "file_hashes_verified": all(file_sha(out / r["file"]) == r["sha256"] for r in result["captured_ranges"])}
    synthetic = MEMORY_BASIC_INFORMATION()
    synthetic.State, synthetic.Type, synthetic.AllocationBase = MEM_COMMIT, MEM_IMAGE, result["module_base"]
    for protection in (PAGE_NOACCESS, 0x20 | PAGE_GUARD, 0x10):
        synthetic.Protect = protection
        assertions[f"reject_protection_{protection:x}"] = not readable(synthetic, result["module_base"])
    synthetic.Protect = 0x20
    assertions["allow_execute_read"] = readable(synthetic, result["module_base"])
    synthetic.AllocationBase = result["module_base"] + 4096
    assertions["reject_other_allocation"] = not readable(synthetic, result["module_base"])
    assertions["reject_output_escape"] = False
    try:
        output_path("C:/capture-not-allowed")
    except ValueError:
        assertions["reject_output_escape"] = True
    doc = {"passed": all(assertions.values()), "assertions": assertions, "tested_target": "self Python process only",
           "manifest_path": str(out / "manifest.json"), "captured_code_bytes": result["captured_code_bytes"],
           "missing_code_bytes": result["missing_code_bytes"], "capture": result,
           "limitations": ["Protected-page skipping was tested with synthetic policy structures; no target protection was changed.",
                           "No Roblox process was launched, opened, read, attached, or captured.",
                           "Read-only acquisition does not suspend the process and cannot prove semantic code coverage."]}
    report = output_path(report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    if not doc["passed"]:
        raise ValueError("Self-test failed")
    return doc


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pid", type=int, help="Explicit already-running PID; the tool never launches it")
    parser.add_argument("--original-pe", help="Exact original module PE path")
    parser.add_argument("--module", help="Explicit loaded module basename, such as Example.exe")
    parser.add_argument("--output", help="New/empty output directory under D:/Scratcher")
    parser.add_argument("--provenance", help="Optional same-hash JSON with validated candidate_ranges RVA subset")
    parser.add_argument("--self-test", action="store_true", help="Capture this script's own Python .text only")
    parser.add_argument("--self-test-report", default="D:/Scratcher/reports/coverage-70/capture-selftest.json")
    args = parser.parse_args()
    if args.self_test:
        if any((args.pid, args.original_pe, args.module, args.output, args.provenance)):
            parser.error("Self-test cannot be combined with target arguments")
        result = self_test(args.self_test_report)
        print(json.dumps({"passed": result["passed"], "captured_code_bytes": result["captured_code_bytes"],
                          "report": args.self_test_report}))
    else:
        if not args.pid or args.pid <= 0 or not all((args.original_pe, args.module, args.output)):
            parser.error("--pid, --original-pe, --module, and --output are required")
        result = capture(args.pid, args.original_pe, args.module, args.output, args.provenance)
        print(json.dumps({"captured_code_bytes": result["captured_code_bytes"], "missing_code_bytes": result["missing_code_bytes"],
                          "manifest": str(output_path(args.output) / "manifest.json")}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, struct.error) as ex:
        print(f"Capture refused/failed: {ex}", file=sys.stderr)
        sys.exit(1)
