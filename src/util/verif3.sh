#!/bin/bash
cd ../../models

echo "KX"
proverif KX.noise.active.pv > KX.noise.active.txt
proverif KX.noise.passive.pv > KX.noise.passive.txt
date

echo "KX1"
proverif KX1.noise.active.pv > KX1.noise.active.txt
proverif KX1.noise.passive.pv > KX1.noise.passive.txt
date

echo "N"
proverif N.noise.active.pv > N.noise.active.txt
proverif N.noise.passive.pv > N.noise.passive.txt
date

echo "NK"
proverif NK.noise.active.pv > NK.noise.active.txt
proverif NK.noise.passive.pv > NK.noise.passive.txt
date

echo "NK1"
proverif NK1.noise.active.pv > NK1.noise.active.txt
proverif NK1.noise.passive.pv > NK1.noise.passive.txt
date

echo "NN"
proverif NN.noise.active.pv > NN.noise.active.txt
proverif NN.noise.passive.pv > NN.noise.passive.txt
date

echo "NX"
proverif NX.noise.active.pv > NX.noise.active.txt
proverif NX.noise.passive.pv > NX.noise.passive.txt
date

cd ../src/util
