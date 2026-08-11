# ci/jenkins/plugins/

This directory holds individual `.hpi` plugin files for Jenkins.  When populated
(by running `download.sh` below, or by committing the files directly), it gives IT
administrators a concrete set of files they can inspect, transfer, and install without
any internet access, Docker daemon, or special tooling.

The `.hpi` files are **not** committed to the repository by default — they are large
binary blobs that change independently of the source code.  Only commit them if your
workflow requires fully offline distribution of a known-good plugin set (similar to
how the `vendor.tar.gz.*` parts ship Rust crate sources).  The `download.sh` script in this
directory is always committed and is enough to regenerate the files on demand.

**Which path for your setup?**

| Scenario | Path |
|----------|------|
| Fully online — no restrictions | A or B |
| Online but no Docker | B |
| Air-gapped with Docker | A |
| Air-gapped without Docker | A (requires `jenkins-plugins.tar.xz` pre-committed to repo) |
| Air-gapped, no networked machine, no Docker | A (requires `jenkins-plugins.tar.xz` pre-committed to repo) |

> **Scenarios 4 & 5 pre-requisite:** Path A's bundling step (`bundle-jenkins-plugins.sh`)
> requires Docker + internet and must be run once on a networked machine.  Commit the
> resulting `jenkins-plugins.tar.xz` + `jenkins-plugins.tar.xz.sha256` to the
> repository root — after that, air-gapped hosts need only `git clone`.

---

## Choosing an installation path

Three paths are supported, listed from most to least automated.

---

### Path A — Admin with Docker (full transitive dependency tree)

**Recommended for fully air-gapped installs.**

Run `bundle-jenkins-plugins.sh` on any machine that has Docker and internet access.
It uses the official `jenkins-plugin-cli` to resolve and download the **complete
transitive dependency tree** — not just the direct plugins listed in `plugins.txt`.
The output is `jenkins-plugins.tar.xz` + `jenkins-plugins.tar.xz.sha256`.

```bash
# On a machine with Docker + internet:
bash ci/jenkins/bundle-jenkins-plugins.sh

# Commit both output files:
git add jenkins-plugins.tar.xz jenkins-plugins.tar.xz.sha256
git commit -m "ci: bundle Jenkins plugins for air-gapped install"
```

After that one-time step, every `git clone` has everything needed:

```bash
# On the air-gapped host:
bash ci/jenkins/install-jenkins-plugins.sh --restart
```

See `ci/jenkins/README.md → "Installing plugins (air-gapped — recommended)"` for the
full Dockerfile and native-install variations.

---

### Path B — Admin without Docker

Use `download.sh` in this directory to populate `.hpi` files for the direct plugins
listed in `ci/jenkins/plugins.txt`.  No Docker required.

**Step 1 — Populate this directory:**

```bash
bash ci/jenkins/plugins/download.sh
```

Optional: re-download even when files already exist:

```bash
bash ci/jenkins/plugins/download.sh --force
```

Optional: point at an internal mirror instead of the Jenkins Update Center:

```bash
bash ci/jenkins/plugins/download.sh --update-center https://mirrors.example.com/jenkins
```

**Step 2 — Install into a running Jenkins instance:**

Copy the `.hpi` files to `$JENKINS_HOME/plugins/` and restart:

```bash
bash ci/jenkins/install-jenkins-plugins.sh --from-dir ci/jenkins/plugins --restart
```

Or copy manually:

```bash
cp ci/jenkins/plugins/*.hpi /var/jenkins_home/plugins/
# Docker:
docker restart <container-name>
# Native:
sudo systemctl restart jenkins
```

Or upload via the Jenkins UI one file at a time:
**Manage Jenkins → Plugins → Advanced → Deploy Plugin → Upload .hpi**

> **Transitive dependency note:** `download.sh` fetches only the direct plugins named
> in `plugins.txt`.  Jenkins resolves their transitive dependencies from the Update
> Center when it starts.  If the Jenkins host has no internet access and no Update
> Center, you need the full bundle from Path A instead.

> **Air-gapped with no networked machine (scenario 5):** `download.sh` requires
> internet access to reach the Jenkins Update Center.  Use Path A instead: run
> `bundle-jenkins-plugins.sh` once on a networked + Docker machine, commit
> `jenkins-plugins.tar.xz`, then run `install-jenkins-plugins.sh` on the air-gapped
> host — no internet or file transfer needed after `git clone`.

**Optional — commit the files for distribution:**

```bash
git add ci/jenkins/plugins/*.hpi
git commit -m "ci: add pre-downloaded plugin files for offline install"
```

---

## What is stored here

| File | Description |
|------|-------------|
| `README.md` | This file |
| `download.sh` | Downloads `.hpi` files for all plugins in `plugins.txt` |
| `*.hpi` | Pre-downloaded plugin files (present only if you ran `download.sh` and committed) |
