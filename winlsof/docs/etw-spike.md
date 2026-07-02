# ETW spike — confirm `Microsoft-Windows-TCPIP` / `AFD` events carry FD/endpoint data

This is the **P1 spike** for [research roadmap item §5](research-roadmap.md): an
ETW-based path to attach real handle values and access modes to socket rows
(replacing today's `unk`).

The goal of P1 is **not** to write the ETW consumer yet. It's to answer one
question with real Windows data — *do the events even contain what we need?* —
before sinking days of Rust FFI into it. If the events expose a (PID, local
addr+port, handle) triplet on socket-create or connect, we can write the
consumer in P2. If they don't, item §5 closes the same way §1 and §2 did, with
the precise gap documented — and we don't have 300 lines of dead unsafe FFI to
delete.

The capture uses **built-in Windows tools** (`logman`, `tracerpt`) — no Rust,
no compile.

## Prerequisites

- Windows 10/11 (any edition).
- An **elevated** PowerShell — `logman start -ets` for a new ETW session
  needs SE_AUDIT_NAME (admin) or membership in *Performance Log Users*. The
  P2 consumer may not need this — that's part of what the spike answers.

## Run the capture

In an **elevated** PowerShell:

```powershell
$out  = "$env:TEMP\winlsof-etw-spike"
New-Item -ItemType Directory -Force -Path $out | Out-Null

# 1) Start a 10-second real-time ETW session against the TCPIP and AFD providers.
#    GUIDs (resolved by name below; using GUIDs avoids name-localization issues):
#      Microsoft-Windows-TCPIP       {2F07E2EE-15DB-40F1-90EF-9D7BA282188A}
#      Microsoft-Windows-Winsock-AFD {E53C6823-7BB8-44BB-90DC-3F86090D48A6}
logman create trace winlsof-spike -ow -o "$out\trace.etl" `
    -p "{2F07E2EE-15DB-40F1-90EF-9D7BA282188A}" 0xffffffffffffffff 0xff `
    -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4 -ets

logman update winlsof-spike -ets `
    -p "{E53C6823-7BB8-44BB-90DC-3F86090D48A6}" 0xffffffffffffffff 0xff

# 2) Generate some real socket traffic so events actually fire.
#    A few socket connects and a couple of UDP datagrams cover the typical events.
1..5 | ForEach-Object {
    try { Test-NetConnection -ComputerName 127.0.0.1 -Port 80 -InformationLevel Quiet | Out-Null } catch {}
}
$udp = [Net.Sockets.UdpClient]::new()
1..3 | ForEach-Object {
    $udp.Send([byte[]](1..4), 4, '127.0.0.1', 9) | Out-Null
}
$udp.Dispose()
Start-Sleep -Seconds 2

# 3) Stop the session.
logman stop winlsof-spike -ets

# 4) Convert ETL -> CSV (one row per event, all fields).
tracerpt "$out\trace.etl" -o "$out\trace.csv" -of CSV -y

# 5) Quick inventory: top event IDs and a peek at one of each.
Import-Csv "$out\trace.csv" |
    Group-Object 'Event Name' |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize | Out-File -Encoding utf8 "$out\summary-event-names.txt"

# Sample one row per distinct event so we can see fields.
Import-Csv "$out\trace.csv" |
    Group-Object 'Event Name' |
    ForEach-Object { $_.Group | Select-Object -First 1 } |
    Export-Csv -NoTypeInformation -Path "$out\sample-one-per-event.csv"

# 6) Show the per-event summary in the console.
Get-Content "$out\summary-event-names.txt"
Write-Host "`nResults in: $out" -ForegroundColor Cyan
Write-Host "  - trace.etl                 (raw)"
Write-Host "  - trace.csv                 (all events, one row each)"
Write-Host "  - summary-event-names.txt   (event count by name)"
Write-Host "  - sample-one-per-event.csv  (one sample row per distinct event)"
```

## What to send back

The three artifacts the script highlights at the end:

1. **`summary-event-names.txt`** — the table of event names + counts. Tells us
   which events the modern providers actually fire and at what rate.
2. **`sample-one-per-event.csv`** — one row per distinct event, including all
   property columns. This is the key one — we look at the column headers
   (the field names) and the values to decide whether the (PID, local
   addr+port, handle) triplet is present on any of them.
3. **(Optional) `trace.csv`** — only if a particular event looks promising and
   you'd like me to look at variation across instances.

You can paste the contents inline, or upload them — they're small (the spike
generates only seconds of traffic, so the CSV is tiny).

## What I'll decide from it

The deciding question is **which event(s), if any, carry all three of**:

- The owning **process ID** (`Process Id` / `ProcessId` / similar column),
- The socket **endpoint** (`LocalAddress` + `LocalPort`, ideally also `RemoteAddress` + `RemotePort`), and
- A **handle** or **object pointer** (`Handle`, `Endpoint`, `Object`, `Tcb` — any kernel-stable identifier we can join on later).

If at least one event-ID covers all three reliably on socket
create/connect/close: **proceed to P2** — write a short-lived ETW consumer in
`lsof-backend-windows`, populate an index, join with `sockets::collect`.

If only the (PID, endpoint) pair is present (no handle/object): the ETW route
only duplicates what IP Helper already gives us, and item §5 closes the same
way §1 did — documented limitation. We don't write the consumer.

If only the (PID, handle) pair is present (no endpoint): we have the inverse
problem — we know which handles belong to which sockets but can't tell which
TCP row maps to which one. Document and move on.

## Cleanup

```powershell
# Stop the session if you re-ran without finishing:
logman stop winlsof-spike -ets 2>$null
logman delete winlsof-spike 2>$null
# Optionally wipe the spike folder:
# Remove-Item -Recurse -Force "$env:TEMP\winlsof-etw-spike"
```

## Why this is the right shape for a P1 spike

The temptation is to start writing the Rust ETW consumer immediately
(`windows-sys` with `Win32_System_Diagnostics_Etw`, `StartTraceW`,
`EnableTraceEx2`, an `EVENT_RECORD` callback parsed with TDH, etc.). That's
several hundred lines of unsafe FFI and Tdh parsing, all of which is wasted if
the events don't contain the right fields. The 5-minute `logman` + `tracerpt`
capture answers the *real* question — does the data exist? — at zero cost. If
the answer is yes, the Rust consumer is straightforward; if no, we close the
gate with the artifact in hand.

This mirrors how items 1 and 2 in the roadmap were investigated: spike against
documented sources first, decide, then implement only the live path.
