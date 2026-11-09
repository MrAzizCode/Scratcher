"""Scratcher stdio test client. Does not use desktop automation or run input binaries."""
import ctypes
import json
import queue
import subprocess
import threading
import time
from ctypes import wintypes


class Client:
    def __init__(self, executable, desktop=None):
        args = [str(executable), "--mcp"]
        if desktop:
            args += ["--desktop", desktop]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, encoding="utf-8", creationflags=subprocess.CREATE_NO_WINDOW)
        self.responses = queue.Queue()
        self.errors = []
        self.sequence = 0
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=lambda: self.errors.append(self.process.stderr.read()), daemon=True).start()
        self.initialization = self.rpc("initialize", {"protocolVersion": "2025-11-25",
            "capabilities": {}, "clientInfo": {"name": "Scratcher-verification", "version": "1"}})
        self.notify("notifications/initialized")

    def _read(self):
        for line in self.process.stdout:
            try:
                self.responses.put(json.loads(line))
            except Exception as error:
                self.responses.put(error)
        self.responses.put(RuntimeError("MCP stdout closed"))

    def notify(self, method, params=None):
        packet = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            packet["params"] = params
        self.process.stdin.write(json.dumps(packet, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def rpc(self, method, params=None, timeout=30):
        self.sequence += 1
        packet = {"jsonrpc": "2.0", "id": self.sequence, "method": method}
        if params is not None:
            packet["params"] = params
        self.process.stdin.write(json.dumps(packet, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        response = self.responses.get(timeout=timeout)
        if isinstance(response, Exception):
            raise response
        if response.get("id") != self.sequence:
            raise RuntimeError("MCP response ID mismatch")
        if "error" in response:
            raise RuntimeError(str(response["error"]))
        return response["result"]

    def tool(self, name, arguments=None, timeout=30):
        response = self.rpc("tools/call", {"name": name, "arguments": arguments or {}}, timeout)
        if response.get("isError"):
            raise RuntimeError(name + ": " + response["content"][0]["text"])
        return response.get("structuredContent", json.loads(response["content"][0]["text"]))

    def memory(self):
        class Counters(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
                "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
                "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage", "PrivateUsage")]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
        handle = kernel.OpenProcess(0x410, False, self.process.pid)
        if not handle:
            return {}
        try:
            counters = Counters()
            counters.cb = ctypes.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return {}
            return {"working_set_mib": counters.WorkingSetSize / 2**20,
                "peak_working_set_mib": counters.PeakWorkingSetSize / 2**20,
                "private_mib": counters.PrivateUsage / 2**20,
                "page_faults": counters.PageFaultCount}
        finally:
            kernel.CloseHandle(handle)

    def close(self):
        if self.process.poll() is None:
            self.process.stdin.close()
            try:
                self.process.wait(5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


def timed(client, name, arguments=None, timeout=30):
    start = time.perf_counter()
    result = client.tool(name, arguments, timeout)
    return result, (time.perf_counter() - start) * 1000
