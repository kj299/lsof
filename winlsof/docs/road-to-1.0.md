# winlsof — road to 1.0

Every winlsof release so far is cut with the `--prerelease` flag. This doc turns
that hedge into a checklist: what 1.0 *means*, the concrete exit criteria, and
the decision record for the one verification gap that stays manual (the
elevation blind spot) with the per-release checkpoint that covers it.

## What 1.0 means

**A stability commitment, not a feature milestone.** At 1.0:

- The **CLI option surface** (every switch in `lsof -h`) and the **machine
  formats** (`-F` field codes, `-J`/`-j` JSON shapes) are stable — a breaking
  change to any of them requires a major bump.
- The platform-limit gates recorded in
  [`research-roadmap.md`](research-roadmap.md) (byte-range locks, socket-FD
  correlation) are **accepted non-goals**, not blockers. 1.0 does not wait for
  kernel-driver territory.
- The release drops `--prerelease` in
  [`winlsof-release.yml`](../../.github/workflows/winlsof-release.yml) (it is
  hardcoded today, deliberately) and the release notes stop calling the binary
  a prerelease.

## Exit criteria

Cut `winlsof-v1.0.0` when — and only when — every box is checked:

| # | Criterion | Status |
|---|---|---|
| 1 | **Verification depth**: the socket differential is a hard gate covering the family and state classes (IPv4 + IPv6; LISTEN/ESTABLISHED/CLOSE_WAIT/FIN_WAIT2/UDP); the coverage gate reports `UNCOVERED: 0`; the unsafe audit passes with a `// SAFETY:` on every backend `unsafe` block. | ✅ shipped in v0.3.0/v0.3.x |
| 2 | **Elevation blind spot dispositioned**: the privilege-hint logic is CI-tested on both elevation branches on every push, and the residue is a documented per-release checkpoint (this doc, below). | ✅ |
| 3 | **Signed releases**: the `AZSIGN_*` secrets are live and a release has shipped with a **signed `lsof.exe`** — the SmartScreen/Defender false-positive story in [`code-signing.md`](code-signing.md) resolved by reputation rather than README workarounds. | ⬜ ops-side (Azure setup) |
| 4 | **Fuzz soak**: ≥ **14 consecutive green nightly deep-fuzz runs** (the 30-minute [`winlsof-fuzz-nightly.yml`](../../.github/workflows/winlsof-fuzz-nightly.yml) job with its accumulating corpus) with no parser findings. Two weeks of soak, restarting the count from any finding's fix. | ⬜ workflow landed 2026-08-22 |
| 5 | **Release-candidate field validation**: the **exact release artifact** (downloaded `lsof.exe`, not a local build) passes the full smoke suite (59 cases today) on real Windows 11 hardware in **both** privilege modes — the per-release checkpoint below — with zero FAIL and zero hangs. | ⬜ per release |
| 6 | **No open correctness findings**: no unledgered differential divergence, no open bug against rendered output, and [`known-limitations.md`](known-limitations.md) current as of the RC. | ⬜ per release |

Items 5–6 are evaluated against the release candidate; items 1–4 are standing
state. When all six hold, the 1.0 cut is: bump versions, update the CHANGELOG,
drop `--prerelease` from the release workflow, tag.

## Decision record: the elevation blind spot

**The gap.** Two smoke cases run only *unelevated*:
`privilege-hint-unelevated` (a plain `-p <pid>` run must print the
"re-run as Administrator" hint on stderr) and `suppress-warnings-dash-w`
(`-w` must suppress it). Hosted `windows-latest` runners always run as
Administrator (with UAC disabled on the image), so both cases SKIP in CI —
permanently. Until v0.3.x, the "55/55 across both modes" claim rested entirely
on manual runs on real hardware, and the `-w` suppression assertion never
executed on any CI push.

**Option considered — a low-privilege CI step.** Run the built binary under a
restricted token on the runner (`runas /trustlevel:0x20000`, or a created
limited local user + credentialed launch) and assert the hint appears.
**Rejected, for a fidelity reason:** the product's check is
`GetTokenInformation(TokenElevation)`, and what that reports for a
SAFER-restricted token on a UAC-disabled image is exactly the kind of
undocumented interaction this project refuses to gate on unverified
(credentialed launches from non-interactive CI sessions are additionally a
known flake class). A red result would debug the *runner's token plumbing*,
not winlsof; a green result would prove an approximation, not the real
unelevated context a user has.

**What shrank instead.** The hint behavior decomposes into a pure predicate ⊗
one token query:

- **The predicate** — hint only when unelevated **and** table mode **and** the
  run does system-wide handle enumeration (not `-i`/`-U`/path lookups),
  suppressed by `-w` — is extracted as
  `wants_privilege_hint()` in `lsof-cli/src/main.rs` and unit-tested through
  the real argv parser on **every CI push, both elevation branches, all
  platforms**, pinning the same argv → decision pairs the two skipped smoke
  cases assert.
- **The residue** is literally one bit: `is_elevated()`
  (`GetTokenInformation(TokenElevation)` in
  `lsof-backend-windows/src/privilege.rs`) returning false for a genuinely
  unelevated token. That is a documented Win32 contract exercised by every
  UAC-aware application, and it is re-validated on real hardware by the
  checkpoint below on every release.

**Bar for revisiting.** Build the low-privilege CI job (landing observe-first
with `continue-on-error`, as the differential did) if either happens: the
manual checkpoint ever catches a real `is_elevated()` regression, or
elevation-conditional *logic* grows beyond this one predicate. Neither has
occurred to date.

## Per-release manual checkpoint: the unelevated pass

Part of cutting any release (and criterion 5 for 1.0). On a real Windows 10/11
x64 machine:

```powershell
# 1. Download lsof.exe + lsof.exe.sha256 from the release page; verify:
(Get-FileHash .\lsof.exe -Algorithm SHA256).Hash.ToLower() -eq (Get-Content .\lsof.exe.sha256).Trim()

# 2. Pass 1 — a NORMAL (non-elevated) PowerShell. This is the pass that
#    actually executes privilege-hint-unelevated and suppress-warnings-dash-w:
cd winlsof\smoketest
.\Invoke-WinlsofSmokeTest.ps1 -Binary <path-to-downloaded>\lsof.exe

# 3. Pass 2 — an ELEVATED PowerShell (Run as administrator), same command.
```

**Pass bar:** zero FAIL and zero hangs in both passes, and every case green in
at least one pass (the per-pass SKIPs are mode-specific by design — see
[`smoketest/README.md`](../smoketest/README.md)). Record the two PASS/FAIL/SKIP
lines in the release notes, as v0.2.0 did (51 unelevated / 53 elevated, 0 FAIL).
