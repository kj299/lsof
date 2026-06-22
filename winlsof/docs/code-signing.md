# Code-signing winlsof release binaries — tracking doc

> Lives as a doc rather than a GitHub Issue because this repository has Issues
> disabled. If Issues are enabled later (**Settings → General → Features →
> Issues**), file this content as one and link back here.

## Why

The `winlsof-v0.1.0` release binary is **unsigned**, which causes friction on
every download:

- **Windows SmartScreen** prompts the user before letting the binary run (only
  *More info → Run anyway* gets past it).
- **Microsoft Defender** flags the downloaded `lsof.exe` as a hacktool / PUA
  and refuses to launch it, because winlsof legitimately does what an
  open-files lister must — enumerate every process's handles, enable
  `SeDebugPrivilege`, and read process memory (for `cwd` / PEB). This is
  exactly the behavior heuristic AV flags, and Sysinternals' own `handle.exe`
  / Process Explorer get the same treatment when downloaded.

A locally built binary isn't flagged (no "mark of the web"), so the issue only
bites distributed copies. The published SHA-256 lets users verify integrity,
but it doesn't help the launch block — currently we tell users to add a
Defender exclusion (`Add-MpPreference -ExclusionPath <path>`), which is
unacceptable long-term.

## Goal

Establish reputation for `lsof.exe` so downloads run without warnings (or
with a one-time, gentler warning), without compromising the release pipeline.

## Options to evaluate

| Option | Cost | Effort | Notes |
|---|---|---|---|
| **EV code-signing certificate** (DigiCert / Sectigo) | ~$200–400/yr | M | Instant SmartScreen reputation; gold standard. Defender PUA may still apply until reputation accrues, but signing makes it appealable. |
| **OV code-signing certificate** | ~$100–250/yr | M | Has to accrue reputation through downloads before SmartScreen quiets down. |
| **Microsoft Trusted Signing** (Azure-hosted, ~$10/mo) | ~$120/yr | M | New Azure service; signing happens in Azure KV via GitHub Actions; supersedes the old "Authenticode in CI" pain. Probably the right move. |
| **SignPath.io community plan** | Free for OSS | M | Hosted signing for OSS projects; uses their cert. Worth applying. |
| **Self-signed + ship the public cert** | $0 | S | Doesn't help SmartScreen; only useful for internal/audit chains. Not recommended. |

## Acceptance criteria

- [ ] Pick a signing approach (Trusted Signing / SignPath / EV cert).
- [ ] Wire signing into `.github/workflows/winlsof-release.yml` so `lsof.exe`
  is signed *before* the release-asset upload step.
- [ ] Verify on a clean Win10/11 box: SmartScreen either doesn't warn or
  shows a one-time "verified publisher" prompt; Defender does **not**
  quarantine a fresh download.
- [ ] Update `winlsof/README.md` "Antivirus / Defender note" once signing
  lands (remove the `Add-MpPreference` workaround, keep the SHA-256
  verification path).
- [ ] Drop the matching note from `.github/workflows/winlsof-release.yml`
  release-notes template.

## Out of scope

- Submitting the binary to Microsoft for [malware analysis](https://www.microsoft.com/en-us/wdsi/filesubmission)
  (the AV-vendor false-positive route) — useful one-time clean-up after
  signing, but not a substitute.
- An MSIX / installer wrapper — winlsof is a single-file CLI; keep it that way.

## References

- Microsoft Trusted Signing: https://learn.microsoft.com/azure/trusted-signing/
- SignPath community plan: https://about.signpath.io/product/community
- Sysinternals discussion of the same heuristic-AV problem: it's why their
  tools historically shipped unsigned for years, then signed under Microsoft.

This tracks the *distribution* fix; nothing about the binary itself is wrong
— v0.1.0 passed the smoke test 36/0/1 on real Windows 11 hardware (both
privilege modes), and the downloaded artifact ran 10/10 once allowed.
