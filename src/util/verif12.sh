#!/bin/bash
cd ../../models

echo "IKpsk2"
proverif IKpsk2.noise.active.pv > IKpsk2.noise.active.txt
proverif IKpsk2.noise.passive.pv > IKpsk2.noise.passive.txt
date

cd ../src/util
