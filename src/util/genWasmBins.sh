#!/bin/bash
echo "[NoiseExplorer] Compiling WASM Binaries..."

cd ../../implementations/wasm
for pattern in ./*; do
	cd $pattern
	wasm-pack build --target web --release --scope noiseexplorer_$pattern
	rm pkg/.gitignore
	cd ..
done