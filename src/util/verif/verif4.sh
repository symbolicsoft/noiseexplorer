#!/bin/bash
cd ../../models

echo "XK"
proverif XK.noise.active.pv > ../results/XK.noise.active.txt
proverif XK.noise.passive.pv > ../results/XK.noise.passive.txt
date

echo "X1K"
proverif X1K.noise.active.pv > ../results/X1K.noise.active.txt
proverif X1K.noise.passive.pv > ../results/X1K.noise.passive.txt
date

echo "X1K1"
proverif X1K1.noise.active.pv > ../results/X1K1.noise.active.txt
proverif X1K1.noise.passive.pv > ../results/X1K1.noise.passive.txt
date

echo "X1N"
proverif X1N.noise.active.pv > ../results/X1N.noise.active.txt
proverif X1N.noise.passive.pv > ../results/X1N.noise.passive.txt
date

echo "X1X"
proverif X1X.noise.active.pv > ../results/X1X.noise.active.txt
proverif X1X.noise.passive.pv > ../results/X1X.noise.passive.txt
date

echo "X1X1"
proverif X1X1.noise.active.pv > ../results/X1X1.noise.active.txt
proverif X1X1.noise.passive.pv > ../results/X1X1.noise.passive.txt
date

cd ../src/util
