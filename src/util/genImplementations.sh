#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
	node noiseExplorer \
		--generate=go --pattern=$pattern \
		> ../implementations/go/$(basename "${pattern}").go
	node noiseExplorer \
		--generate=rs --pattern=$pattern \
		> ../implementations/rust/$(basename "${pattern}").rs
done
cd ../implementations/go
go get -d ./...
cd ../../src/util
