# AV / EDR Whitelisting Guide

This page is for enterprise administrators who see oxide-sloc flagged by Carbon Black
Cloud, Microsoft Defender, CrowdStrike Falcon, McAfee / Trellix, Malwarebytes, or
other endpoint security products.

## Windows vs. RHEL Linux — the detection profile is different

**Windows** detections happen because oxide-sloc ships a bundled Rust toolchain
(`toolchain/rust-toolchain-windows-x64.tar.gz.*`). `install.sh` extracts this into
`.tools/` using a shell script. The resulting PE files (`cargo.exe`, `rustup.exe`, etc.)
are unsigned and appear in a non-standard path — a pattern Carbon Black, McAfee, and
Trellix associate with PUA/adware droppers. Additionally, building from source on Windows
causes Cargo to compile 67 small PE executables in `target/release/build/` (one per crate
that has a `build.rs` file). These cannot be pre-signed; static-AI scanners (Malwarebytes,
McAfee heuristics) flag small unsigned PEs regardless of origin.

**RHEL Linux** has none of these problems. The bundled Linux toolchain contains ELF
binaries, not PE files. Carbon Black for Linux uses behavioral analytics (process trees,
network, file access), not PE reputation scoring. Malwarebytes does not run on Linux.
The build scripts compiled during `cargo build` are ELF executables that Linux AV does
not scan with the same heuristics applied to Windows PEs. Source builds on RHEL work
without any AV intervention.

**Recommended deployment strategy:**

| Platform | Recommended install path |
|----------|--------------------------|
| RHEL / Linux (air-gapped) | Source build — `bash scripts/install.sh` compiles from vendored Rust sources |
| Windows (managed enterprise, air-gapped) | Pre-built signed binary in `dist/` — `bash scripts/install.sh` extracts it; no Rust compilation occurs |
| Windows (developer machine) | Source build works — add `target/` to Malwarebytes exclusions (see below) |

## Why Windows flags happen (detail)

The extracted binaries (`.tools/cargo/bin/cargo.exe`, `.tools/cargo/bin/rustup.exe`,
etc.) are standard Rust project binaries compiled by the Rust project team, but:

- They are extracted by a shell script to a non-standard path, which matches a
  behavioural pattern common to PUA/adware droppers.
- Until Authenticode code signing is in place for the bundled toolchain, the PE files
  carry no digital signature, giving them a low reputation score in EDR databases.

The main `oxide-sloc` binary may also trigger heuristic detections (VirusTotal shows
2/71 as of v1.5.0 — both are ML-score / behavioural false positives with no signature
match).

## Recommended path for Windows managed environments (air-gapped)

**Use the pre-built binary committed to `dist/` in the repository.**
`install.sh` automatically uses `dist/oxide-sloc-windows-x64.zip` when present,
extracting the signed `oxide-sloc.exe` and exiting — no Rust toolchain is extracted,
no build scripts are compiled, no unsigned PE files are created. Carbon Black, McAfee,
and Trellix have nothing to flag.

The `dist/` archive is committed to `main` after each release by the CI pipeline. A
plain `git clone` or `git pull` is all that is needed; no additional download step is
required on the air-gapped machine.

Verify the extracted binary against the release checksums:

```powershell
# After install.sh extracts the binary:
(Get-FileHash .\oxide-sloc.exe -Algorithm SHA256).Hash
# Compare against SHA256SUMS.txt from the same release tag on GitHub
```

On internet-connected machines, also verify the GitHub Attestation (requires `gh` CLI):

```bash
gh attestation verify oxide-sloc.exe --repo NimaShafie/oxide-sloc
```

Or the cosign bundle (from the GitHub Release page):

```bash
cosign verify-blob --bundle oxide-sloc-windows-x86_64.exe.bundle \
  oxide-sloc-windows-x86_64.exe
```

## Developer machines — Malwarebytes and `target/`

If you are building from source on a Windows developer machine, Malwarebytes Free may
flag small PE files in `target/release/build/` (Rust build scripts compiled by Cargo).
These are not malware — they are intermediate compiler outputs that exist only during
the build and are never committed to the repo.

Fix: add a folder exclusion in Malwarebytes (no admin required for Malwarebytes Free):

1. Open Malwarebytes → **Settings** (gear icon) → **Security** tab → **Exclusions**
2. Click **Add Exclusion** → **Add a Folder Exclusion**
3. Select: `C:\path\to\oxide-sloc\target`
4. Click OK

Also recommended for build performance:

```powershell
# Run as Administrator (Windows Defender)
Add-MpPreference -ExclusionPath "C:\path\to\oxide-sloc\target"
```

## Carbon Black Cloud — path exclusions for Windows source builds

If you must build from source on a Windows machine managed by Carbon Black (rather than
using the pre-built binary from `dist/`), add path-based exclusions in the CBC console
before running `install.sh`.

1. Open **Carbon Black Cloud** → **Enforce** → **Policies**.
2. Select the applicable policy → **Prevention** tab → **Permission Rules**.
3. Add **Allow** rules for the following paths (adjust drive letter as needed):

   | Path | Notes |
   |------|-------|
   | `C:\path\to\oxide-sloc\.tools\cargo\bin\*` | cargo.exe, rustup.exe proxy copies |
   | `C:\path\to\oxide-sloc\.tools\rustup\toolchains\*\bin\*` | rustc.exe, rustdoc.exe, etc. |

4. Alternatively, approve by SHA-256 hash:
   - Open **Investigate** → **Alerts**, locate the flagged file.
   - Click the hash → **Actions** → **Add to Approved List**.

The exact SHA-256 hashes for the bundled toolchain parts are in
`toolchain/checksums.sha256` in the repository.

## Microsoft Defender — adding folder exclusions

```powershell
# Run as Administrator
Add-MpPreference -ExclusionPath "C:\path\to\oxide-sloc\.tools"
```

Remove the exclusion after the build completes (Defender will re-scan once you remove
the exclusion, but the compiled `oxide-sloc.exe` in the repo root is clean):

```powershell
Remove-MpPreference -ExclusionPath "C:\path\to\oxide-sloc\.tools"
```

## CrowdStrike Falcon — adding IOA exclusions

1. **Falcon Console** → **Endpoint Security** → **Prevention Policies** →
   **Custom IOA Exclusions**.
2. Add a process path exclusion matching:
   - `*\.tools\cargo\bin\cargo.exe`
   - `*\.tools\cargo\bin\rustup.exe`
3. Scope the exclusion to the specific host group where oxide-sloc is installed.

## Submitting false positives to vendors

The following vendors have been notified of the false positive detection on the
oxide-sloc binary. If you encounter a detection on a new version, please submit the
binary hash to the relevant vendor portal:

| Vendor | Submission URL |
|--------|---------------|
| McAfee / Trellix (enterprise) | https://www.mcafee.com/enterprise/en-us/threat-intelligence/false-positive.html |
| Skyhigh Security (SWG) | https://www.mcafee.com/enterprise/en-us/threat-intelligence/false-positive.html |
| Trapmine | fp@trapmine.com (company acquired — email only; web portal offline) |
| Carbon Black / VMware | Via CBC console: Investigate → Reputation → Submit for Review |
| Microsoft Defender | https://www.microsoft.com/en-us/wdsi/filesubmission |
| Malwarebytes | https://www.malwarebytes.com/lp/false-positive-submissions |

## Verifying binary authenticity without AV trust

The oxide-sloc release pipeline produces the following verifiable artefacts for
every release:

| Artefact | What it proves |
|----------|---------------|
| `SHA256SUMS.txt` | Integrity — the binary has not been modified |
| `*.sig` (GPG detached) | Authenticity — signed by the project GPG key |
| `*.bundle` (cosign) | Provenance — signed by GitHub OIDC, tied to the exact CI run |
| GitHub Attestation | SLSA provenance — binary was produced by this repo's CI workflow |

The GPG public key is `oxide-sloc-signing-key.asc` in each release.

## Code signing status

| Platform | Status |
|----------|--------|
| Windows Authenticode | Pending certificate — planned once project meets CA eligibility |
| macOS Developer ID | Pending Apple Developer account |
| GPG detached signature | Active (if `GPG_PRIVATE_KEY` secret is set) |
| Sigstore cosign (keyless) | Active — included in every release |
| SLSA provenance attestation | Active — verifiable via `gh attestation verify` |

Once Windows Authenticode signing is active, the bundled Rust toolchain binaries
will also be signed before archiving, eliminating the Carbon Black false positive
without requiring any exclusion configuration.
