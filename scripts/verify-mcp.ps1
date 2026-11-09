param([string]$Executable='D:/Scratcher/dist-v0.4/ScratcherMCP.exe',[string]$Sample='D:/Scratcher/dist-v0.4/samples/ScratcherSample.exe')
$ErrorActionPreference='Stop'
$psi=[Diagnostics.ProcessStartInfo]::new()
$psi.FileName=$Executable
$psi.ArgumentList.Add('--mcp')
$psi.UseShellExecute=$false
$psi.RedirectStandardInput=$true
$psi.RedirectStandardOutput=$true
$psi.RedirectStandardError=$true
$utf8=[Text.UTF8Encoding]::new($false)
$psi.StandardInputEncoding=$utf8
$psi.StandardOutputEncoding=$utf8
$psi.StandardErrorEncoding=$utf8
$process=[Diagnostics.Process]::Start($psi)
$stderr=$process.StandardError.ReadToEndAsync()
$script:nextId=100
function Read-Rpc([int]$ExpectedErrorCode=0) {
 $read=$process.StandardOutput.ReadLineAsync()
 if (-not $read.Wait(30000)) { throw 'MCP response timeout' }
 if ($null -eq $read.Result) { throw 'MCP process closed stdout unexpectedly' }
 $response=$read.Result | ConvertFrom-Json -Depth 50
 if ($response.jsonrpc -ne '2.0') { throw 'Invalid JSON-RPC response' }
 if ($ExpectedErrorCode) {
  if ($response.error.code -ne $ExpectedErrorCode) { throw "Expected error $ExpectedErrorCode, got $($read.Result)" }
 } elseif ($response.error) { throw ($response.error | ConvertTo-Json -Compress) }
 return $response
}
function Send-Rpc([object]$Message,[int]$ExpectedErrorCode=0) {
 $process.StandardInput.WriteLine(($Message | ConvertTo-Json -Depth 30 -Compress))
 $process.StandardInput.Flush()
 if (-not $Message.Contains('id')) { return }
 $response=Read-Rpc $ExpectedErrorCode
 if ($null -ne $response.id -and $response.id -ne $Message.id) { throw 'Response id mismatch' }
 return $response
}
function Invoke-Tool([string]$Name,[hashtable]$Arguments=@{}) {
 $script:nextId++
 $response=Send-Rpc @{jsonrpc='2.0';id=$script:nextId;method='tools/call';params=@{name=$Name;arguments=$Arguments}}
 if ($response.result.isError) { throw "$Name failed: $($response.result.content[0].text)" }
 if ($response.result.structuredContent -isnot [pscustomobject]) { throw "$Name returned non-object structuredContent" }
 return $response.result.structuredContent
}
try {
 $null=Send-Rpc @{jsonrpc='2.0';id=0;method='tools/list'} -ExpectedErrorCode -32002
 $init=Send-Rpc @{jsonrpc='2.0';id=1;method='initialize';params=@{protocolVersion='2025-11-25';capabilities=@{};clientInfo=@{name='scratcher-verification';version='1'}}}
 if ($init.result.serverInfo.name -ne 'Scratcher' -or $init.result.serverInfo.version -ne '0.4.0') { throw 'Incorrect MCP identity' }
 $null=Send-Rpc @{jsonrpc='2.0';id=2;method='tools/list'} -ExpectedErrorCode -32002
 Send-Rpc @{jsonrpc='2.0';method='notifications/initialized'}
 $list=Send-Rpc @{jsonrpc='2.0';id=3;method='tools/list'}
 if ($list.result.tools.Count -ne 135) { throw 'Tool discovery failed' }
 $names=@($list.result.tools.name)
 foreach ($name in @('open_binary','decompile','get_control_flow','get_cross_references','get_call_graph','set_comment','list_annotations','set_function_signature','get_function_types','search_bytes','stage_patch','export_patched')) {
  if ($name -notin $names) { throw "Missing tool: $name" }
 }
 if (@($names | Sort-Object -Unique).Count -ne $names.Count) { throw 'Duplicate tool names' }
 $null=Send-Rpc @{jsonrpc='2.0';id=4;method='tools/call';params=@{name='missing-tool'}} -ExpectedErrorCode -32602
 $null=Send-Rpc @{jsonrpc='2.0';id=5;method='tools/call';params=@{name='read_bytes';arguments=$null}} -ExpectedErrorCode -32602
 $open=Invoke-Tool 'open_binary' @{path=$Sample}
 $functions=Invoke-Tool 'list_functions' @{limit=10000}
 $target=$functions.items | Where-Object name -EQ 'add_numbers' | Select-Object -First 1
 if (-not $target) { throw 'Exported sample function not indexed' }
 $decompile=Invoke-Tool 'decompile' @{address=$target.address}
 $cached=Invoke-Tool 'decompile' @{address=$target.address}
 if (-not $cached.cached) { throw 'Cache not used' }
 $invalid=Send-Rpc @{jsonrpc='2.0';id=6;method='tools/call';params=@{name='read_bytes';arguments=@{address=$target.address;count=-1}}}
 if (-not $invalid.result.isError) { throw 'Invalid arguments accepted' }
 $invalidBoolean=Send-Rpc @{jsonrpc='2.0';id=7;method='tools/call';params=@{name='get_cross_references';arguments=@{address=$target.address;outgoing=1}}}
 if (-not $invalidBoolean.result.isError) { throw 'Invalid boolean arguments accepted' }
 $graph=Invoke-Tool 'get_control_flow' @{address=$target.address;instruction_budget=4096}
 if (-not $graph.nodes.Count) { throw 'Control flow returned no blocks' }
 $references=Invoke-Tool 'get_cross_references' @{address=$target.address;instruction_budget=10000}
 $callGraph=Invoke-Tool 'get_call_graph' @{instruction_budget=10000}
 $note='MCP verification: تحليل'
 $null=Invoke-Tool 'set_comment' @{address=$target.address;text=$note}
 $null=Invoke-Tool 'set_bookmark' @{address=$target.address;name='Verification function'}
 $notes=Invoke-Tool 'list_annotations'
 if (($notes | ConvertTo-Json -Depth 20) -notlike "*$note*") { throw 'UTF-8 comment round trip failed' }
 $null=Invoke-Tool 'set_function_signature' @{address=$target.address;declaration='int add_numbers(int left, int right);'}
 $types=Invoke-Tool 'get_function_types' @{address=$target.address}
 if (-not $types.signature) { throw 'Missing function signature' }
 $pattern=Invoke-Tool 'search_bytes' @{pattern='??';limit=1}
 $null=Invoke-Tool 'stage_patch' @{address=$target.address;bytes='90'}
 $patches=Invoke-Tool 'list_patches'
 if (-not $patches.items.Count) { throw 'Staged patch missing' }
 $null=Invoke-Tool 'remove_patch' @{address=$target.address}
 $process.StandardInput.WriteLine('{broken-json')
 $process.StandardInput.Flush()
 $null=Read-Rpc -ExpectedErrorCode -32700
 $process.StandardInput.WriteLine(('x' * (1024 * 1024 + 16)))
 $process.StandardInput.Flush()
 $null=Read-Rpc -ExpectedErrorCode -32600
 Send-Rpc @{jsonrpc='2.0';method='notifications/cancelled';params=@{requestId=7;reason='Completed request'}}
 $null=Send-Rpc @{jsonrpc='2.0';id='after-malformed';method='ping'}
 $report=[ordered]@{date=(Get-Date -Format 'yyyy-MM-ddTHH:mm:ssK');tool_count=$list.result.tools.Count;sample=$Sample;sample_size=$open.size;metadata_load_ms=$open.load_ms;first_decompile_ms=$decompile.elapsed_ms;cache_used=$cached.cached;graph_blocks=$graph.nodes.Count;signature=$types.signature;pseudocode=$decompile.code;verification='MCP lifecycle, discovery, metadata, pseudocode, cache, graphs, references, Unicode comments, types, search, staged patches, schema validation, malformed messages, size bounds, and cancellation notification passed'}
 $report | ConvertTo-Json -Depth 10 | Set-Content D:/Scratcher/reports/v0.4/stdio-mcp.json -Encoding utf8
 $report | ConvertTo-Json -Depth 10
} finally {
 $process.StandardInput.Close()
 if (-not $process.WaitForExit(5000)) { $process.Kill(); $process.WaitForExit() }
 if ($stderr.IsCompleted -and $stderr.Result) { Write-Verbose $stderr.Result }
 $process.Dispose()
}