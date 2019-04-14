#!/bin/bash
cd ../../models

echo "N"
proverif N.noise.active.pv > ../results/N.noise.active.txt
proverif N.noise.passive.pv > ../results/N.noise.passive.txt
date

echo "NN"
proverif NN.noise.active.pv > ../results/NN.noise.active.txt
proverif NN.noise.passive.pv > ../results/NN.noise.passive.txt
date

echo "NK"
proverif NK.noise.active.pv > ../results/NK.noise.active.txt
proverif NK.noise.passive.pv > ../results/NK.noise.passive.txt
date

echo "NX"
proverif NX.noise.active.pv > ../results/NX.noise.active.txt
proverif NX.noise.passive.pv > ../results/NX.noise.passive.txt
date

echo "KX"
proverif KX.noise.active.pv > ../results/KX.noise.active.txt
proverif KX.noise.passive.pv > ../results/KX.noise.passive.txt
date

echo "NK1"
proverif NK1.noise.active.pv > ../results/NK1.noise.active.txt
proverif NK1.noise.passive.pv > ../results/NK1.noise.passive.txt
date

echo "KX1"
proverif KX1.noise.active.pv > ../results/KX1.noise.active.txt
proverif KX1.noise.passive.pv > ../results/KX1.noise.passive.txt
date

cd ../src/util
