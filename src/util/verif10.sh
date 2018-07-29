#!/bin/bash
cd ../../models

echo "INpsk1"
proverif INpsk1.noise.active.pv > INpsk1.noise.active.txt
proverif INpsk1.noise.passive.pv > INpsk1.noise.passive.txt
date

echo "INpsk2"
proverif INpsk2.noise.active.pv > INpsk2.noise.active.txt
proverif INpsk2.noise.passive.pv > INpsk2.noise.passive.txt
date

echo "IXpsk2"
proverif IXpsk2.noise.active.pv > IXpsk2.noise.active.txt
proverif IXpsk2.noise.passive.pv > IXpsk2.noise.passive.txt
date

cd ../src/util
