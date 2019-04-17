#!/bin/bash
cd ../../models

echo "XNpsk3"
proverif XNpsk3.noise.active.pv > ../results/XNpsk3.noise.active.txt
proverif XNpsk3.noise.passive.pv > ../results/XNpsk3.noise.passive.txt
date

cd ../src/util
