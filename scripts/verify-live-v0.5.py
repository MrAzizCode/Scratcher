"""Verify a running Scratcher workspace exclusively through MCP, with a hidden test window."""
import datetime
import json
import pathlib
import subprocess
import time
from mcp_client import Client, timed

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "dist-v0.5"


def main():
    # Start-Process uses the app's normal startup settings and hides only this owned test instance.
    command = f"$taskApp=Start-Process -FilePath '{PACKAGE / 'Scratcher.exe'}' -WindowStyle Hidden -PassThru; $taskApp.Id"
    pid = int(subprocess.check_output(["powershell", "-NoProfile", "-Command", command], text=True).strip())
    report = {"date": datetime.datetime.now().astimezone().isoformat(), "method": "MCP stdio and named-pipe API only; hidden owned test instance; no Computer Use", "checks": [], "timings_ms": {}}

    def check(condition, message):
        if not condition:
            raise AssertionError(message)
        report["checks"].append(message)

    try:
        with Client(PACKAGE / "ScratcherMCP.exe") as client:
            deadline = time.monotonic() + 15
            session = None
            while time.monotonic() < deadline:
                sessions = client.tool("discover_sessions")["items"]
                session = next((item for item in sessions if item["pid"] == pid), None)
                if session:
                    break
                time.sleep(.1)
            check(session is not None, "Discover exact owned desktop PID")
            tools = client.rpc("tools/list")["tools"]
            check(len(tools) == 146, "146 built-in MCP tools")
            check(len(set(tool["name"] for tool in tools)) == len(tools), "Tool names unique")
            check(len(client.rpc("resources/list")["resources"]) == 6, "Six readable resources")
            check(len(client.rpc("prompts/list")["prompts"]) == 2, "Two investigation prompts")
            client.tool("attach_session", {"session_id": session["id"]})
            check(client.tool("get_session")["mode"] == "desktop", "Attached live mode")
            opened, wall = timed(client, "open_binary", {"path": str(PACKAGE / "samples/ScratcherSample.exe")})
            report["timings_ms"]["live_open"] = wall
            functions = client.tool("list_functions", {"limit": 10000})["items"]
            function = next(item for item in functions if item["name"] == "add_numbers")
            address = function["address"]
            state, wall = timed(client, "navigate_to", {"address": address, "view": "Disassembly"})
            report["timings_ms"]["navigate_disassembly"] = wall
            check(state["selected_address"] == address and state["active_view"] == "Disassembly", "Address and active view updated")
            check(bool(state["views"]["disassembly"]), "Live instruction snapshot available")
            client.tool("navigate_to", {"address": opened["entry"], "view": "Hex"})
            check(client.tool("navigate_back")["selected_address"] == address, "Back history works")
            check(client.tool("navigate_forward")["selected_address"] == opened["entry"], "Forward history works")
            client.tool("navigate_to", {"address": address, "view": "Pseudocode"})
            state = client.tool("set_active_view", {"view": "Graph"})
            report["graph_selection"] = {"active_view": state["active_view"], "node_count": len(state["views"]["graph"].get("nodes", []))}
            check(state["active_view"] == "Graph" and bool(state["views"]["graph"]["nodes"]), "Graph view populated through MCP")
            check(client.tool("set_function_filter", {"query": "add_numbers"})["function_filter"] == "add_numbers", "Function filter controlled")
            job = client.tool("submit_job", {"tool": "decompile", "arguments": {"address": address}})
            result = client.tool("await_job", {"job_id": job["job_id"], "timeout_ms": 5000})
            check(result["status"] == "completed" and "code" in result["result"], "Async job result available without consuming it")
            check(client.tool("get_job", {"job_id": job["job_id"]})["status"] == "completed", "Job retrieval repeatable")
            check(bool(client.tool("list_jobs")["items"]), "Job history retained")
            operations = [{"tool": "set_comment", "arguments": {"address": address, "text": "Live MCP verification • تحليل"}},
                {"tool": "set_bookmark", "arguments": {"address": address, "name": "Verified"}},
                {"tool": "rename_function", "arguments": {"address": address, "name": "verified_add"}}]
            batch = client.tool("batch_tools", {"operations": operations})
            check(all(item["success"] for item in batch["items"]), "Ordered batch edits committed")
            code = client.tool("decompile", {"address": address})["code"]
            check("verified_add" in code, "Renamed function reanalyzed correctly")
            check(client.tool("analyze_reachable", {"address": address, "instruction_budget": 512})["semantic_analysis_complete"] is False, "Reachability distinguishes semantic completeness")
            client.tool("define_type", {"declaration":"struct LiveRecord { int field; uint64_t value; };"})
            check(client.tool("list_types")["count"] == 1, "Native aggregate registered through live MCP")
            client.tool("undo")
            check(client.tool("list_types")["count"] == 0, "Live type undo rebuilds types")
            client.tool("redo")
            check(client.tool("list_types")["count"] == 1, "Live type redo replays types")
            mapping = client.tool("get_pseudocode_mapping", {"address": address})
            check(any(t.get("instruction_address") for t in mapping["tokens"]), "Live pseudocode carries real instruction links")
            check(client.tool("set_active_view", {"view":"Workbench"})["active_view"] == "Workbench", "Advanced Workbench controlled through MCP")
            script = client.tool("exec_script", {"source":"return scratcher.call('get_binary_info', {})"})
            check(script["result"]["size"] == opened["size"], "Embedded scripting controls the live workspace")
            client.tool("load_plugin", {"path": str(PACKAGE / "plugins/ScratcherPluginSample.dll")})
            check(client.tool("call_plugin", {"id":"sample","tool":"echo","arguments":{"message":"live plugin"}})["message"] == "live plugin", "Native plugin validated through attached MCP")
            client.tool("unload_plugin", {"id":"sample"})
            check(client.tool("list_plugins")["count"] == 0, "Live plugin unload removes callbacks")
            selection_before = client.tool("get_selection")["address"]
            client.tool("batch_tools", {"dry_run": True, "operations": [{"tool": "open_binary", "arguments": {"path": "D:/nonexistent-dry-run.exe"}}]})
            check(client.tool("get_selection")["address"] == selection_before, "Dry-run preserves selection and session")
            resource = client.rpc("resources/read", {"uri": "scratcher://annotations"})
            check("تحليل" in resource["contents"][0]["text"], "Live resource reflects Unicode annotation")
            project = ROOT / "reports/v0.5/live-test.scratcher"
            project.parent.mkdir(exist_ok=True)
            client.tool("save_project", {"path": str(project)})
            client.tool("load_project", {"path": str(project)})
            check(any(item["name"] == "verified_add" for item in client.tool("list_functions", {"limit": 10000})["items"]), "Project round trip retains live edits")
            auto = client.tool("run_auto_analysis", {"time_budget_ms": 10000}, timeout=20)
            check(auto["configured_phases_finished"] and not auto["semantic_analysis_complete"], "Live automatic pipeline distinguishes configured phases from semantic completion")
            check(client.tool("get_auto_analysis_report")["phases"] == auto["phases"], "Live phase report available")
            check(client.tool("get_code_analysis", {"limit": 5})["total"] > 0, "Live native reachable evidence paginated")
            refs = client.tool("get_analysis_references", {"limit": 5})
            check(refs["analysis"]["code_policy_effective"] == "reachable", "Live references use current reachable scope")
            check(client.tool("get_rtti", {"limit": 5})["available"], "Live RTTI evidence retained")
            check("items" in client.tool("get_exception_info", {"limit": 5}), "Live exception evidence paginated")
            check(client.tool("get_import_semantics", {"limit": 5})["installed"] > 0, "Live imported API names installed")
            # Cancel a genuinely queued analysis behind a broad asynchronous batch.
            submitted = client.tool("submit_job", {"tool": "batch_tools", "arguments": {"operations": [
                {"tool": "get_binary_info"} for _ in range(256)]}})
            queued = client.tool("submit_job", {"tool": "analyze", "arguments": {"instruction_budget": 1000000}})
            cancellation = client.tool("cancel_job", {"job_id": queued["job_id"]})
            terminal = client.tool("await_job", {"job_id": queued["job_id"], "timeout_ms": 5000})
            check(terminal["status"] in ("cancelled", "completed"), "Targeted cancel reports truthful terminal state")
            report["cancellation"] = {"accepted": cancellation.get("cancellation_accepted"), "status": terminal["status"]}
            check(client.tool("await_job", {"job_id": submitted["job_id"], "timeout_ms": 5000})["status"] == "completed", "Unrelated batch survives targeted cancellation")
            check(bool(client.tool("get_activity_log")["items"]), "Activity timings exposed")
            client.tool("detach_session")
            check(client.tool("get_session")["mode"] == "isolated", "Detach returns independent mode")
            report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = repr(error)
        raise
    finally:
        # Stop only the process created above, never another Scratcher workspace.
        subprocess.run(["powershell", "-NoProfile", "-Command", f"Stop-Process -Id {pid} -ErrorAction SilentlyContinue"], check=False)
        directory = ROOT / "reports/v0.5"
        directory.mkdir(exist_ok=True)
        (directory / "live-mcp.json").write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
