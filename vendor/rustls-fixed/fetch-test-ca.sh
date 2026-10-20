#!/bin/bash
# The rustls fork's own tests (`cargo test --manifest-path
# vendor/rustls-fixed/rustls/Cargo.toml --lib`) read upstream's test PKI, keys
# and CRLs included, with include_bytes!. The keys and CRLs (*.key, *.pem) are
# kept out of this repository by .gitignore, so the tests could not compile
# from a checkout and CI never ran them. This fetches the upstream release the
# fork is based on, checks the tarball against its pinned SHA-256 and that
# every test-ca file already here is upstream's (the keys must belong to these
# certificates), and adds the rest. Run from anywhere:
#   vendor/rustls-fixed/fetch-test-ca.sh
set -euo pipefail
cd "$(dirname "$0")"
TAG=v/0.23.46
SHA256=f3289f357c49d2e28c8737b92320e720d8a9b09032240229d4e22bbd71bf1a17
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSfL --retry 3 -o "$tmp/rustls.tar.gz" \
    "https://codeload.github.com/rustls/rustls/tar.gz/refs/tags/$TAG"
echo "$SHA256  $tmp/rustls.tar.gz" | sha256sum -c --quiet -
tar -xzf "$tmp/rustls.tar.gz" -C "$tmp"
up=$(echo "$tmp"/rustls-*/test-ca)
git ls-files test-ca | while read -r f; do
    cmp -s "$f" "$up/${f#test-ca/}" || {
        echo "fetch-test-ca: $f is not upstream $TAG's" >&2
        exit 1
    }
done
n=0
while read -r f; do
    install -D -m 0644 "$up/$f" "test-ca/$f"
    n=$((n + 1))
done < <(cd "$up" && find . -type f \( -name '*.key' -o -name '*.pem' \) | sed 's#^\./##')
echo "test-ca: $n keys and CRLs from rustls $TAG"
