#!/bin/bash
cd ../../models

echo "IKpsk2"
proverif IKpsk2.noise.active.pv > ../results/IKpsk2.noise.active.txt
proverif IKpsk2.noise.passive.pv > ../results/IKpsk2.noise.passive.txt
date

cd ../src/util
