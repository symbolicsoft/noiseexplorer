#!/bin/bash
echo "[NoiseExplorer] Running Go Tests..."
cd ../../implementations/go/tests
for pattern in *; do
    cd $pattern
    go mod init $pattern &> /dev/null
    go get -d &> /dev/null
    go run *
    cd ../
done
echo "[NoiseExplorer] Running Rust Tests..."
cd ../../rs
for pattern in ./*/; do
    cd $pattern
    cargo test
    cd ..
done
echo "[NoiseExplorer] Running WASM Tests..."
cd ../wasm
for pattern in ./*; do
    cd $pattern
    wasm-pack test --release --headless --chrome
    cd ..
done