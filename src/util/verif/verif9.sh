#!/bin/bash
cd ../../models

echo "KNpsk0"
proverif KNpsk0.noise.active.pv > ../results/KNpsk0.noise.active.txt
proverif KNpsk0.noise.passive.pv > ../results/KNpsk0.noise.passive.txt
date

echo "KNpsk2"
proverif KNpsk2.noise.active.pv > ../results/KNpsk2.noise.active.txt
proverif KNpsk2.noise.passive.pv > ../results/KNpsk2.noise.passive.txt
date

echo "KKpsk0"
proverif KKpsk0.noise.active.pv > ../results/KKpsk0.noise.active.txt
proverif KKpsk0.noise.passive.pv > ../results/KKpsk0.noise.passive.txt
date

echo "KKpsk2"
proverif KKpsk2.noise.active.pv > ../results/KKpsk2.noise.active.txt
proverif KKpsk2.noise.passive.pv > ../results/KKpsk2.noise.passive.txt
date

echo "KXpsk2"
proverif KXpsk2.noise.active.pv > ../results/KXpsk2.noise.active.txt
proverif KXpsk2.noise.passive.pv > ../results/KXpsk2.noise.passive.txt
date

cd ../src/util