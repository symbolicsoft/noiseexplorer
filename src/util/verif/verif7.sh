#!/bin/bash
cd ../../models

echo "Npsk0"
proverif Npsk0.noise.active.pv > ../results/Npsk0.noise.active.txt
proverif Npsk0.noise.passive.pv > ../results/Npsk0.noise.passive.txt
date

echo "Kpsk0"
proverif Kpsk0.noise.active.pv > ../results/Kpsk0.noise.active.txt
proverif Kpsk0.noise.passive.pv > ../results/Kpsk0.noise.passive.txt
date

echo "Xpsk1"
proverif Xpsk1.noise.active.pv > ../results/Xpsk1.noise.active.txt
proverif Xpsk1.noise.passive.pv > ../results/Xpsk1.noise.passive.txt
date

echo "NNpsk0"
proverif NNpsk0.noise.active.pv > ../results/NNpsk0.noise.active.txt
proverif NNpsk0.noise.passive.pv > ../results/NNpsk0.noise.passive.txt
date

echo "NNpsk2"
proverif NNpsk2.noise.active.pv > ../results/NNpsk2.noise.active.txt
proverif NNpsk2.noise.passive.pv > ../results/NNpsk2.noise.passive.txt
date

cd ../src/util
