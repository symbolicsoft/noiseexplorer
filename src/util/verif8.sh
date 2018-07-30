#!/bin/bash
cd ../../models

echo "NKpsk0"
proverif NKpsk0.noise.active.pv > NKpsk0.noise.active.txt
proverif NKpsk0.noise.passive.pv > NKpsk0.noise.passive.txt
date

echo "NKpsk2"
proverif NKpsk2.noise.active.pv > NKpsk2.noise.active.txt
proverif NKpsk2.noise.passive.pv > NKpsk2.noise.passive.txt
date

echo "NXpsk2"
proverif NXpsk2.noise.active.pv > NXpsk2.noise.active.txt
proverif NXpsk2.noise.passive.pv > NXpsk2.noise.passive.txt
date

echo "XNpsk3"
proverif XNpsk3.noise.active.pv > XNpsk3.noise.active.txt
proverif XNpsk3.noise.passive.pv > XNpsk3.noise.passive.txt
date

echo "XKpsk3"
proverif XKpsk3.noise.active.pv > XKpsk3.noise.active.txt
proverif XKpsk3.noise.passive.pv > XKpsk3.noise.passive.txt
date

echo "XXpsk3"
proverif XXpsk3.noise.active.pv > XXpsk3.noise.active.txt
proverif XXpsk3.noise.passive.pv > XXpsk3.noise.passive.txt
date

cd ../src/util
