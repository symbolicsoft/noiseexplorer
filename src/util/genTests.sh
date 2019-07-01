#!/bin/bash
echo "[NoiseExplorer] Running Go Tests..."
cd ..
cd ../implementations/go/tests
go get -d ./...
cd ../../../src
for pattern in ../implementations/go/tests/*.go; do
    go run $pattern
done

echo "[NoiseExplorer] Running Rust Tests..."
cd ../implementations/rs
for pattern in ./*; do
    cd $pattern
    cargo test
    cd ..
done

echo "[NoiseExplorer] Running WASM Tests..."
cd ../../implementations/wasm
for pattern in ./*; do
    cd $pattern
    wasm-pack test --release --headless --chrome
    cd ..
done