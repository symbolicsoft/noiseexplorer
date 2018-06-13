#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
	node noiseExplorer.js --render=message \
		--pattern=../patterns/$(basename "${pattern}") \
		--activeModel=../models/$(basename "${pattern}").active.pv \
		--activeResults=../models/$(basename "${pattern}").active.txt \
		--passiveResults=../models/$(basename "${pattern}").passive.txt
	
	node noiseExplorer --render=handshake \
		--activeResults=../models/$(basename "${pattern}").active.txt \
		--passiveResults=../models/$(basename "${pattern}").passive.txt \
		--pattern=../patterns/$(basename "${pattern}")
done
cd util
