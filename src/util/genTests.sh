#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
    node noiseExplorer \
		--generate=go --testgen --pattern=$pattern \
		> ../implementations/go/tests/$(basename "${pattern}").go
done
for pattern in ../patterns/*.noise; do
    node noiseExplorer \
		--generate=rs --testgen --pattern=$pattern
done
echo " OK"
echo "[NoiseExplorer] Running Go Tests..."
cd ../implementations/go/tests
go get -d ./...
cd ../../../src
for pattern in ../implementations/go/tests/*.go; do
    go run $pattern
done
echo "[NoiseExplorer] Running Rust Tests..."
cd ../implementations/rs/tests
for pattern in ./*; do
    cd $pattern
    cargo test
    cd ..
done
cd util

