#!/bin/bash
cd ../../models

echo "IN"
proverif IN.noise.active.pv > ../results/IN.noise.active.txt
proverif IN.noise.passive.pv > ../results/IN.noise.passive.txt
date

echo "IX"
proverif IX.noise.active.pv > ../results/IX.noise.active.txt
proverif IX.noise.passive.pv > ../results/IX.noise.passive.txt
date

echo "X"
proverif X.noise.active.pv > ../results/X.noise.active.txt
proverif X.noise.passive.pv > ../results/X.noise.passive.txt
date

echo "XX"
proverif XX.noise.active.pv > ../results/XX.noise.active.txt
proverif XX.noise.passive.pv > ../results/XX.noise.passive.txt
date

echo "KK1"
proverif KK1.noise.active.pv > ../results/KK1.noise.active.txt
proverif KK1.noise.passive.pv > ../results/KK1.noise.passive.txt
date

echo "KN"
proverif KN.noise.active.pv > ../results/KN.noise.active.txt
proverif KN.noise.passive.pv > ../results/KN.noise.passive.txt
date

echo "NX1"
proverif NX1.noise.active.pv > ../results/NX1.noise.active.txt
proverif NX1.noise.passive.pv > ../results/NX1.noise.passive.txt
date

cd ../src/util
