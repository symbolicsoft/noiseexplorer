#!/bin/bash
cd ../../models

echo "IKpsk1"
proverif IKpsk1.noise.active.pv > ../results/IKpsk1.noise.active.txt
proverif IKpsk1.noise.passive.pv > ../results/IKpsk1.noise.passive.txt
date

cd ../src/util
