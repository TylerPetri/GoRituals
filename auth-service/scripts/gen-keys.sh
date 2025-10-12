#!/usr/bin/env bash
set -euo pipefail

ALG=${1:?usage: $0 rs|ed [out_dir] [kid]}
OUT_DIR=${2:-/secrets}
KID=${3:-kid-$(date +%Y%m%d%H%M%S)}

mkdir -p "$OUT_DIR"

case "$ALG" in
  rs)
    # RS256: PKCS#8 private + SPKI public
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$OUT_DIR/${KID}.key"
    openssl pkey -in "$OUT_DIR/${KID}.key" -pubout -out "$OUT_DIR/${KID}.pub"
    ;;
  ed)
    # Ed25519: PKCS#8 private + SPKI public
    openssl genpkey -algorithm Ed25519 -out "$OUT_DIR/${KID}.key"
    openssl pkey -in "$OUT_DIR/${KID}.key" -pubout -out "$OUT_DIR/${KID}.pub"
    ;;
  *)
    echo "usage: $0 rs|ed [out_dir] [kid]" >&2; exit 1;;
esac

chmod 600 "$OUT_DIR/${KID}.key"
echo "wrote: $OUT_DIR/${KID}.key (private) and $OUT_DIR/${KID}.pub (public)"
