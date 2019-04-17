#!/bin/bash
cd ../../models

echo "INpsk1"
proverif INpsk1.noise.active.pv > ../results/INpsk1.noise.active.txt
proverif INpsk1.noise.passive.pv > ../results/INpsk1.noise.passive.txt
date


cd ../src/util
