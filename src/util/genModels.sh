#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
	node ../src/noiseExplorer \
		--generate=proverif --pattern=$pattern --attacker=active \
		> ../models/$(basename "${pattern}").active.pv
	node ../src/noiseExplorer \
		--generate=proverif --pattern=$pattern --attacker=passive \
		> ../models/$(basename "${pattern}").passive.pv
done
cd util
