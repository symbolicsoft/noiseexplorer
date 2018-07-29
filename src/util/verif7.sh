#!/bin/bash
cd ../../models

echo "Npsk0"
proverif Npsk0.noise.active.pv > Npsk0.noise.active.txt
proverif Npsk0.noise.passive.pv > Npsk0.noise.passive.txt
date

echo "Kpsk0"
proverif Kpsk0.noise.active.pv > Kpsk0.noise.active.txt
proverif Kpsk0.noise.passive.pv > Kpsk0.noise.passive.txt
date

echo "Xpsk1"
proverif Xpsk1.noise.active.pv > Xpsk1.noise.active.txt
proverif Xpsk1.noise.passive.pv > Xpsk1.noise.passive.txt
date

echo "NNpsk0"
proverif NNpsk0.noise.active.pv > NNpsk0.noise.active.txt
proverif NNpsk0.noise.passive.pv > NNpsk0.noise.passive.txt
date

echo "NNpsk2"
proverif NNpsk2.noise.active.pv > NNpsk2.noise.active.txt
proverif NNpsk2.noise.passive.pv > NNpsk2.noise.passive.txt
date

cd ../src/util
