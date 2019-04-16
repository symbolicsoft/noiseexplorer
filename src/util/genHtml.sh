#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
	node noiseExplorer.js --render \
		--pattern=../patterns/$(basename "${pattern}") \
		--activeModel=../models/$(basename "${pattern}").active.pv \
		--activeResults=../results/$(basename "${pattern}").active.txt \
		--passiveResults=../results/$(basename "${pattern}").passive.txt
done
cd util
