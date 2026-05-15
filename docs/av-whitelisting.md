# AV / EDR Whitelisting Guide

This page is for enterprise administrators and users who see oxide-sloc flagged by Carbon Black
Cloud, Microsoft Defender, CrowdStrike Falcon, McAfee / Trellix, Malwarebytes, or other endpoint
security products during installation or use.

## Windows vs. RHEL Linux — the detection profile is different

**RHEL / Linux** — no AV/EDR action needed. The bundled Linux toolchain contains ELF binaries.
Carbon Black for Linux uses behavioral analytics (process trees, network, file access), not PE
reputation scoring. The build scripts compiled during `cargo build` are ELF executables that Linux
AV does not scan with Windows PE heuristics. Source builds on RHEL work without any AV intervention.

**Windows** — `install.sh` extracts a pre-built `oxide-sloc.exe` from `dist/oxide-sloc-windows-x64.zip`
(committed to the repository). No Rust toolchain (`cargo.exe`, `rustup.exe`) is ever written to disk.
The only PE file that AV/EDR sees is `oxide-sloc.exe` itself — and when it carries an Authenticode
signature, EDR software passes it without any exclusion or admin intervention.

## Recommended paths — no admin rights required

| Platform | Recommended path | Admin required? |
|----------|-----------------|----------------|
| RHEL / Linux | Source build — `bash scripts/run.sh` | No |
| Windows — signed binary | `bash scripts/run.sh` extracts `dist/oxide-sloc-windows-x64.zip` containing a signed `oxide-sloc.exe`. EDR passes it without any exclusion. | No |
| Windows — unsigned binary | `oxide-sloc.exe` may trigger SmartScreen on first launch. Submit to vendor for whitelisting, or activate signing (see below). | No |

## How Authenticode signing eliminates the detection (no admin needed on user's machine)

The signing happens in CI before the Windows binary is committed to `dist/`:

1. A maintainer sets the `WINDOWS_CERTIFICATE` (base64 PFX) and `WINDOWS_CERTIFICATE_PASSWORD`
   secrets in GitHub Actions settings.
2. The `update-dist.yml` CI workflow builds `oxide-sloc.exe` (MSVC target) and calls `signtool`
   to sign it before packaging it into `dist/oxide-sloc-windows-x64.zip`.
3. The signed zip is committed to the repository — every `git clone` now contains a signed binary.
4. On the user's machine, `install.sh` calls `trust_ca_cert()` — which imports
   `certs/sloc-ca.crt` (the public Root CA cert, committed to the repo) into the current user's
   Windows certificate store using the .NET X509Store API. **No administrator rights required**
   for the CurrentUser store.
5. When `install.sh` extracts `oxide-sloc.exe`, EDR sees: signed by OxideSLOC Root CA → trusted
   CA in user store → signature valid → binary allowed. No exclusion, no dialog, no admin needed.

Authenticode verification is **local** — signatures are embedded in the PE file. Air-gapped
machines verify them without any network call to the CA. OCSP/CRL revocation checks are
best-effort; Windows allows the binary gracefully when the revocation server is unreachable.

## Activating signing (maintainer steps)

Generate a self-signed certificate (free, no CA purchase needed):

```bash
bash scripts/internal/gen-signing-cert.sh
```

This creates a root CA and a code-signing leaf cert, bundles them into a PFX, and prints exact
next steps. Afterward:

1. Commit the public CA cert:
   ```bash
   git add certs/sloc-ca.crt
   git commit -m "chore: add Authenticode root CA certificate"
   ```
2. In the GitHub repository: **Settings → Secrets and variables → Actions → New repository secret**
   - `WINDOWS_CERTIFICATE` = contents of `_signing/sloc-sign.pfx.b64`
   - `WINDOWS_CERTIFICATE_PASSWORD` = the PFX password set during cert generation
3. Re-run `update-dist.yml` (Actions tab → Update dist bundles → Run workflow). This rebuilds
   and commits a signed `oxide-sloc.exe` to `dist/oxide-sloc-windows-x64.zip`.
4. After `git pull`, all Windows installs will extract the signed binary.

**Trusting the certificate on air-gapped Windows endpoints:**

Signatures from a self-signed cert are cryptographically valid but require a one-time CA
import per endpoint (or a single GPO push for domain-joined machines):

```powershell
# Run as Administrator — imports sloc-ca.crt from the repo
Import-Certificate -FilePath .\certs\sloc-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
```

`install.sh` handles the per-user import automatically (no admin needed) via the .NET
X509Store API. The per-machine import above is for IT administrators managing fleet deployments.

After import, verify the binary:

```powershell
(Get-AuthenticodeSignature .\oxide-sloc.exe).Status   # Valid
```

## For administrators managing multiple endpoints

If AV/EDR still flags `oxide-sloc.exe` (e.g., before signing is activated), the following
options are available. These require console/policy admin access.

### Windows Defender — file exclusion

```powershell
# Requires Administrator
Add-MpPreference -ExclusionPath "C:\path\to\oxide-sloc\oxide-sloc.exe"
Add-MpPreference -ExclusionPath "C:\path\to\oxide-sloc\target"
```

`target/` may be flagged during a source build (Rust emits small PE build-scripts per crate).
Remove the exclusion after the build completes.

### Carbon Black Cloud — path-based permission rules

1. Open **Carbon Black Cloud** → **Enforce** → **Policies**.
2. Select the applicable policy → **Prevention** tab → **Permission Rules**.
3. Add an **Allow** rule for the oxide-sloc binary path:

   | Path | Notes |
   |------|-------|
   | `C:\path\to\oxide-sloc\oxide-sloc.exe` | The main binary — only file needed on Windows |

4. Alternatively, approve by SHA-256: **Investigate** → **Alerts** → locate the flagged file →
   click the hash → **Actions** → **Add to Approved List**.

### CrowdStrike Falcon — custom IOA exclusions

1. **Falcon Console** → **Endpoint Security** → **Prevention Policies** → **Custom IOA Exclusions**.
2. Add a process path exclusion for `*\oxide-sloc\oxide-sloc.exe`.
3. Scope the exclusion to the specific host group where oxide-sloc is installed.

### Malwarebytes — folder exclusion for `target/` (source builds only)

Applies only if building from source on Windows. During `cargo build`, Malwarebytes Free may
flag small PE build scripts in `target/release/build/` (Rust compiles one per crate).

1. Open Malwarebytes → **Settings** (gear icon) → **Security** tab → **Exclusions**
2. Click **Add Exclusion** → **Add a Folder Exclusion**
3. Select: `C:\path\to\oxide-sloc\target`

## Submitting false positives to vendors

| Vendor | Submission |
|--------|-----------|
| Microsoft Defender | https://www.microsoft.com/en-us/wdsi/filesubmission |
| Malwarebytes | https://www.malwarebytes.com/lp/false-positive-submissions |
| McAfee / Trellix (enterprise) | https://www.mcafee.com/enterprise/en-us/threat-intelligence/false-positive.html |
| Carbon Black / VMware | CBC console: Investigate → Reputation → Submit for Review |
| Trapmine | fp@trapmine.com (web portal offline — email only) |

## Code signing status

| Component | Status |
|-----------|--------|
| `oxide-sloc.exe` (Windows release binary in `dist/`) | Signed when `WINDOWS_CERTIFICATE` secret is set in `update-dist.yml` |
| `oxide-sloc.exe` (full release via `release.yml`) | Signed when `WINDOWS_CERTIFICATE` secret is set |
| GPG detached signature (releases) | Active when `GPG_PRIVATE_KEY` secret is set |
| Sigstore cosign (keyless, releases) | Active — included in every GitHub Release |
| SLSA provenance attestation (releases) | Active — verifiable via `gh attestation verify` |
| macOS Developer ID | Pending Apple Developer account |
| Linux toolchain PE binaries (Windows) | Not applicable — Windows no longer extracts the Rust toolchain |

Once `WINDOWS_CERTIFICATE` is set and `update-dist.yml` is re-run, `oxide-sloc.exe` in `dist/`
will carry an Authenticode signature — no exclusion configuration needed on any endpoint,
regardless of admin rights.
