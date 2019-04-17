#!/bin/bash
cd ../../models

echo "KKpsk0"
proverif KKpsk0.noise.active.pv > ../results/KKpsk0.noise.active.txt
proverif KKpsk0.noise.passive.pv > ../results/KKpsk0.noise.passive.txt
date

cd ../src/util
