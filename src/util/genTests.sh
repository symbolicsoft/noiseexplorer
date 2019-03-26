#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
    node noiseExplorer \
		--generate=go --testgen --pattern=$pattern \
		> ../implementations/go/tests/$(basename "${pattern}").go
done
echo " OK (GO TESTS GENERATED)"
for pattern in ../patterns/*.noise; do
	mkdir ../implementations/rs/tests/$(basename "${pattern}")
    node noiseExplorer \
		--generate=rs --testgen --pattern=$pattern
done
echo " OK (RUST TESTS GENERATED)"
echo "[NoiseExplorer] Running Go Tests..."
cd ../implementations/go/tests
go get -d ./...
cd ../../../src
for pattern in ../implementations/go/tests/*.go; do
    go run $pattern
done
#run cargo test for each dir
cd util

