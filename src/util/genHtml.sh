#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
	node noiseExplorer --render \
		--activeResults=../models/$(basename "${pattern}").active.txt \
		--passiveResults=../models/$(basename "${pattern}").passive.txt \
		--pattern=../patterns/$(basename "${pattern}") \
		> html/patterns/$(basename "${pattern}").html
done
cd util
