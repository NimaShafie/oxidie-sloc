#!/usr/bin/env bash
# Generate a self-signed code-signing certificate for oxide-sloc Authenticode signing.
#
# Run once (as the maintainer) on any machine with OpenSSL installed.
# The generated files land in _signing/ (gitignored).
# Only sloc-ca.crt is safe to commit — everything else must stay secret.
#
# Usage:
#   bash scripts/internal/gen-signing-cert.sh           # normal
#   bash scripts/internal/gen-signing-cert.sh --force   # overwrite existing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="$REPO_ROOT/_signing"

# ── sanity checks ────────────────────────────────────────────────────────────

if ! command -v openssl &>/dev/null; then
    echo "ERROR: openssl not found. Install OpenSSL and re-run." >&2
    exit 1
fi

echo "Using $(openssl version)"
echo ""

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" 2>/dev/null || true  # chmod is a no-op on Windows NTFS but harmless

if [[ -f "$OUT_DIR/sloc-ca.key" && "${1:-}" != "--force" ]]; then
    echo "ERROR: $OUT_DIR/sloc-ca.key already exists."
    echo "       Re-run with --force to regenerate (invalidates the old cert chain)." >&2
    exit 1
fi

# ── parameters ───────────────────────────────────────────────────────────────

CA_CN="OxideSLOC Root CA"
LEAF_CN="OxideSLOC Code Signing"
CA_DAYS=3650    # 10 years
LEAF_DAYS=1095  # 3 years

echo "Certificate subjects:"
echo "  CA  : $CA_CN"
echo "  Leaf: $LEAF_CN"
echo ""

# Prompt for PFX password
PFX_PASS=""
while [[ -z "$PFX_PASS" ]]; do
    read -rsp "Enter PFX password (stored as WINDOWS_CERTIFICATE_PASSWORD): " PFX_PASS
    echo ""
    [[ -z "$PFX_PASS" ]] && echo "Password must not be empty." >&2
done
read -rsp "Confirm password: " PFX_PASS2
echo ""
if [[ "$PFX_PASS" != "$PFX_PASS2" ]]; then
    echo "ERROR: Passwords do not match." >&2
    exit 1
fi
echo ""

# ── write OpenSSL config file (avoids -addext and process substitution) ──────

CFG="$OUT_DIR/openssl.cnf"
cat > "$CFG" <<EOF
[ req ]
default_bits       = 4096
prompt             = no
distinguished_name = dn_ca
x509_extensions    = v3_ca

[ dn_ca ]
CN = $CA_CN
O  = oxide-sloc
C  = US

[ v3_ca ]
basicConstraints       = critical,CA:TRUE,pathlen:0
keyUsage               = critical,keyCertSign,cRLSign
subjectKeyIdentifier   = hash

[ dn_leaf ]
CN = $LEAF_CN
O  = oxide-sloc
C  = US

[ v3_leaf ]
basicConstraints       = CA:FALSE
extendedKeyUsage       = critical,codeSigning
keyUsage               = critical,digitalSignature
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
EOF

# ── generate Root CA ─────────────────────────────────────────────────────────

echo "[1/5] Generating root CA private key (4096-bit RSA)..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 \
    -out "$OUT_DIR/sloc-ca.key"

echo "[2/5] Self-signing root CA certificate (${CA_DAYS} days)..."
openssl req -new -x509 \
    -config "$CFG" \
    -key "$OUT_DIR/sloc-ca.key" \
    -out "$OUT_DIR/sloc-ca.crt" \
    -days "$CA_DAYS"

# ── generate leaf code-signing cert ──────────────────────────────────────────

echo "[3/5] Generating leaf signing key (2048-bit RSA)..."
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "$OUT_DIR/sloc-sign.key"

echo "[4/5] Signing leaf certificate with root CA..."
# Use a separate req config so the DN is picked up without a prompt
LEAF_CFG="$OUT_DIR/openssl-leaf.cnf"
cat > "$LEAF_CFG" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
distinguished_name = dn_leaf

[ dn_leaf ]
CN = $LEAF_CN
O  = oxide-sloc
C  = US
EOF

openssl req -new \
    -config "$LEAF_CFG" \
    -key "$OUT_DIR/sloc-sign.key" \
    -out "$OUT_DIR/sloc-sign.csr"

openssl x509 -req \
    -in "$OUT_DIR/sloc-sign.csr" \
    -CA "$OUT_DIR/sloc-ca.crt" \
    -CAkey "$OUT_DIR/sloc-ca.key" \
    -CAcreateserial \
    -out "$OUT_DIR/sloc-sign.crt" \
    -days "$LEAF_DAYS" \
    -extfile "$CFG" \
    -extensions v3_leaf

echo "[5/5] Bundling into PFX (leaf + CA chain)..."
openssl pkcs12 -export \
    -out "$OUT_DIR/sloc-sign.pfx" \
    -inkey "$OUT_DIR/sloc-sign.key" \
    -in "$OUT_DIR/sloc-sign.crt" \
    -certfile "$OUT_DIR/sloc-ca.crt" \
    -passout "pass:$PFX_PASS" \
    -name "OxideSLOC Code Signing"

# Base64-encode the PFX for the GitHub Secret
base64 -w0 "$OUT_DIR/sloc-sign.pfx" > "$OUT_DIR/sloc-sign.pfx.b64" 2>/dev/null || \
    base64 "$OUT_DIR/sloc-sign.pfx" | tr -d '\n\r' > "$OUT_DIR/sloc-sign.pfx.b64"

# Copy the public CA cert to the repo root so it can be committed
cp "$OUT_DIR/sloc-ca.crt" "$REPO_ROOT/sloc-ca.crt"

# ── summary ──────────────────────────────────────────────────────────────────

LEAF_EXPIRY="$(openssl x509 -in "$OUT_DIR/sloc-sign.crt" -noout -enddate | cut -d= -f2)"
CA_EXPIRY="$(openssl x509 -in "$OUT_DIR/sloc-ca.crt"   -noout -enddate | cut -d= -f2)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done. Files written to: _signing/"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  PUBLIC (safe to commit):"
echo "    sloc-ca.crt           copied to repo root ← git add this"
echo ""
echo "  SECRET (never commit — keep these offline):"
echo "    _signing/sloc-ca.key          root CA private key"
echo "    _signing/sloc-sign.key        leaf signing key"
echo "    _signing/sloc-sign.pfx        PFX bundle"
echo "    _signing/sloc-sign.pfx.b64   base64 PFX  ← WINDOWS_CERTIFICATE secret"
echo ""
echo "  Cert validity:"
echo "    Leaf (signing):  expires $LEAF_EXPIRY"
echo "    Root CA:         expires $CA_EXPIRY"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  NEXT STEPS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1. Commit the public CA cert:"
echo "       git add sloc-ca.crt"
echo "       git commit -m \"chore: add Authenticode root CA certificate\""
echo ""
echo "  2. Set GitHub Actions secrets:"
echo "       WINDOWS_CERTIFICATE          <- paste content of _signing/sloc-sign.pfx.b64"
echo "       WINDOWS_CERTIFICATE_PASSWORD <- the password you just entered"
echo ""
echo "  3. On each air-gapped Windows endpoint (run PowerShell as Admin):"
echo "       Import-Certificate -FilePath sloc-ca.crt -CertStoreLocation Cert:\LocalMachine\Root"
echo ""
echo "  4. Verify a signed binary:"
echo "       (Get-AuthenticodeSignature .\oxide-sloc.exe).Status   # should print: Valid"
echo ""
