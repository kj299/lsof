# Code-signing winlsof release binaries — tracking doc

> Tracked as [issue #3](https://github.com/kj299/lsof/issues/3). This doc holds
> the detail; the issue holds the state.

## Status (2026-08-30): OPTIONAL — deferred by choice

**Signing is not a 1.0 blocker and is not currently planned.** winlsof ships
**unsigned `lsof.exe` + a published SHA-256** as a deliberate, privacy-conscious
default: any publicly-trusted signing certificate requires identity validation
that puts the maintainer's legal name and city/state/country permanently and
publicly on every binary (a CA/Browser Forum requirement, not Microsoft's), and
signing buys only *reduced download friction* — never integrity, which the
SHA-256 already provides. See *Why signing is optional* in
[`road-to-1.0.md`](road-to-1.0.md).

The rest of this doc is the **runbook, kept ready** in case the friction ever
justifies signing. Preferred order if pursued: **(a)** sign behind a business
entity (LLC name on the cert, not a person's) via an OV certificate; **(b)**
relicense `winlsof/` to an OSI license to unblock the free SignPath Foundation
program; **(c)** the individual Azure Artifact Signing path below, accepting the
personal-identity exposure. The release workflow is already wired for (c) and
no-ops until the `AZSIGN_*` secrets exist, so shipping unsigned needs no change.

## Decision (2026-07-19, superseded 2026-08-30 → optional): Azure Artifact Signing

**Chosen: Azure Artifact Signing** (the service formerly named Microsoft
Trusted Signing), Basic tier ~$9.99/mo. Why the field narrowed to it:

- **EV eliminated.** Microsoft removed EV's instant SmartScreen reputation in
  March 2024 — EV now builds reputation exactly like OV, so its price premium
  buys nothing for this use case.
- **OV eliminated.** For a US individual it is dominated by Artifact Signing:
  more expensive, hardware-token key custody, no first-party CI integration.
  Only relevant as a fallback outside the USA/Canada.
- **SignPath Foundation (free, OSS) blocked.** Requires an OSI-approved
  license; winlsof ships as `LicenseRef-lsof` (the custom lsof/Purdue license,
  permissive but not OSI). Relicensing `winlsof/` to MIT/Apache-2.0 would
  unblock it — deliberately not taken on for now.
- **Artifact Signing fits.** Individual developers in the USA/Canada are
  eligible (reconfirmed after the April 2025 org-only restriction was lifted);
  identity-tied reputation survives its daily cert rotation; first-party
  GitHub Actions integration (`azure/artifact-signing-action@v2`). Note the
  publisher name on the binary is the verified **legal name** (no custom CN),
  and *no* option grants instant SmartScreen trust anymore — reputation
  accrues over weeks of clean downloads regardless.

### What is already wired (this repo)

`.github/workflows/winlsof-release.yml` signs `lsof.exe` before the SHA-256 is
computed and verifies the signature, **gated on repository secrets** — until
they exist the steps no-op and releases ship unsigned as before. Required
secrets (Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `AZSIGN_TENANT_ID` | Entra tenant ID |
| `AZSIGN_CLIENT_ID` | App-registration (service principal) client ID |
| `AZSIGN_CLIENT_SECRET` | Its client secret |
| `AZSIGN_ENDPOINT` | Account region endpoint, e.g. `https://eus.codesigning.azure.net/` |
| `AZSIGN_ACCOUNT` | Artifact Signing account name |
| `AZSIGN_PROFILE` | Certificate profile name |

### Azure setup runbook (manual, one-time, ~few business days for KYC)

1. Azure subscription — **pay-as-you-go, not trial** (trial subscriptions
   stall identity validation), billing account type **Individual**, legal
   name/address exactly as they should appear on the certificate.
2. Register the `Microsoft.CodeSigning` resource provider; create an
   **Artifact Signing account** (Basic) in a supported region; note the
   region endpoint.
3. Assign yourself **Artifact Signing Identity Verifier**; create a **New
   identity validation → Individual** (portal only) and complete KYC.
4. Create a **certificate profile** (Public Trust) bound to the validated
   identity.
5. Create an Entra **app registration** + client secret; grant it **Trusted
   Signing Certificate Profile Signer** on the account. (Upgrade path:
   swap the client secret for OIDC federated credentials later.)
6. Add the six `AZSIGN_*` repository secrets — the next tag push signs.

### After the first signed release

- Submit the signed `lsof.exe` to Microsoft's
  [false-positive portal](https://www.microsoft.com/wdsi/filesubmission) to
  clear the Defender hacktool/PUA heuristic (signing makes this appealable).
- Verify on a clean Win10/11 box (SmartScreen tone, Defender behavior).
- Update the README "Antivirus / Defender note" and the release-notes
  template in `winlsof-release.yml` (drop "the binary is unsigned"; keep
  SHA-256 verification).
- Expect SmartScreen warnings to soften, not vanish, until download
  reputation accrues.

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

## Options originally evaluated (superseded by the decision above)

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
