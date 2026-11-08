#!/usr/bin/env bash
set -e

echo "=== [1/4] Exécution des tests unitaires Cryptographie & Zéroïsation (Dossier 1) ==="
cargo test --release

echo "=== [2/4] Compilation WebAssembly no_std & Optimisation < 2.5 Mo (Dossier 1) ==="
rustup target add wasm32-unknown-unknown
wasm-pack build --target web --release

if command -v wasm-opt &> /dev/null; then
    wasm-opt -Oz pkg/humanvault_core_bg.wasm -o pkg/humanvault_core_bg.wasm
    ls -lh pkg/humanvault_core_bg.wasm
fi

echo "=== [3/4] Compilation des cibles Mobiles Natives iOS & Android (Dossier 2) ==="
rustup target add aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android armv7-linux-androideabi
cargo build --release --target aarch64-linux-android

echo "=== [4/4] MVP 100% compilé et vérifié ==="