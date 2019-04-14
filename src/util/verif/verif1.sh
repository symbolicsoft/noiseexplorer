#!/bin/bash
cd ../../models

echo "IK"
proverif IK.noise.active.pv > ../results/IK.noise.active.txt
proverif IK.noise.passive.pv > ../results/IK.noise.passive.txt
date

echo "I1K"
proverif I1K.noise.active.pv > ../results/I1K.noise.active.txt
proverif I1K.noise.passive.pv > ../results/I1K.noise.passive.txt
date

echo "I1K1"
proverif I1K1.noise.active.pv > ../results/I1K1.noise.active.txt
proverif I1K1.noise.passive.pv > ../results/I1K1.noise.passive.txt
date

echo "I1N"
proverif I1N.noise.active.pv > ../results/I1N.noise.active.txt
proverif I1N.noise.passive.pv > ../results/I1N.noise.passive.txt
date

echo "I1X"
proverif I1X.noise.active.pv > ../results/I1X.noise.active.txt
proverif I1X.noise.passive.pv > ../results/I1X.noise.passive.txt
date

echo "I1X1"
proverif I1X1.noise.active.pv > ../results/I1X1.noise.active.txt
proverif I1X1.noise.passive.pv > ../results/I1X1.noise.passive.txt
date

cd ../src/util
