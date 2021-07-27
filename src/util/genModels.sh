#!/bin/bash
echo "[NoiseExplorer] Generating models..."
cd ..
for pattern in ../patterns/*.noise; do
	node noiseExplorer \
		--generate=pv --pattern=$pattern --attacker=active
	node noiseExplorer \
		--generate=pv --pattern=$pattern --attacker=passive
done
cd util
