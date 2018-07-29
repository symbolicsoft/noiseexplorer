#!/bin/bash
cd ../../models

echo "IKpsk1"
proverif IKpsk1.noise.active.pv > IKpsk1.noise.active.txt
proverif IKpsk1.noise.passive.pv > IKpsk1.noise.passive.txt
date

cd ../src/util
