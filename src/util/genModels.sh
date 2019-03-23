#!/bin/bash
cd ..
for pattern in ../patterns/*.noise; do
	node noiseExplorer \
		--generate=pv --pattern=$pattern --attacker=active \
		> ../models/$(basename "${pattern}").active.pv
	node noiseExplorer \
		--generate=pv --pattern=$pattern --attacker=passive \
		> ../models/$(basename "${pattern}").passive.pv
done
cd util
