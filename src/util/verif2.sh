#!/bin/bash
cd ../../models

echo "IX1"
proverif IX1.noise.active.pv > IX1.noise.active.txt
proverif IX1.noise.passive.pv > IX1.noise.passive.txt

echo "K"
proverif K.noise.active.pv > K.noise.active.txt
proverif K.noise.passive.pv > K.noise.passive.txt

echo "K1K"
proverif K1K.noise.active.pv > K1K.noise.active.txt
proverif K1K.noise.passive.pv > K1K.noise.passive.txt

echo "K1K1"
proverif K1K1.noise.active.pv > K1K1.noise.active.txt
proverif K1K1.noise.passive.pv > K1K1.noise.passive.txt

echo "K1N"
proverif K1N.noise.active.pv > K1N.noise.active.txt
proverif K1N.noise.passive.pv > K1N.noise.passive.txt

echo "K1X"
proverif K1X.noise.active.pv > K1X.noise.active.txt
proverif K1X.noise.passive.pv > K1X.noise.passive.txt

echo "K1X1"
proverif K1X1.noise.active.pv > K1X1.noise.active.txt
proverif K1X1.noise.passive.pv > K1X1.noise.passive.txt

cd ../src/util
