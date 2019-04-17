#!/bin/bash
cd ../../models

echo "INpsk1"
proverif INpsk1.noise.active.pv > ../results/INpsk1.noise.active.txt
proverif INpsk1.noise.passive.pv > ../results/INpsk1.noise.passive.txt
date

echo "INpsk2"
proverif INpsk2.noise.active.pv > ../results/INpsk2.noise.active.txt
proverif INpsk2.noise.passive.pv > ../results/INpsk2.noise.passive.txt
date

echo "IXpsk2"
proverif IXpsk2.noise.active.pv > ../results/IXpsk2.noise.active.txt
proverif IXpsk2.noise.passive.pv > ../results/IXpsk2.noise.passive.txt
date

cd ../src/util