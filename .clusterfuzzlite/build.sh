#!/bin/bash -eu
# Every target in fuzz/, built with the sanitizer ClusterFuzzLite asks for,
# each with its seeds (fuzz/seeds/<target>/) as its starting corpus
cd "$SRC/pqcrypta-proxy/fuzz"
# The image's nightly predates APIs the proxy uses (AtomicUsize::try_update,
# stable since 1.95): the nightly the proxy's build hosts run, here too
TOOLCHAIN=nightly-2026-10-02
rustup toolchain install "$TOOLCHAIN" --profile minimal
cargo +"$TOOLCHAIN" fuzz build -O
for target in fuzz_targets/*.rs; do
    name=$(basename "$target" .rs)
    cp "target/x86_64-unknown-linux-gnu/release/$name" "$OUT/"
    if [ -d "seeds/$name" ]; then
        (cd "seeds/$name" && zip -q -r "$OUT/${name}_seed_corpus.zip" .)
    fi
done
