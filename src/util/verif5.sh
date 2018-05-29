#!/bin/bash
cd ../../models

echo "IN"
proverif IN.noise.active.pv > IN.noise.active.txt
proverif IN.noise.passive.pv > IN.noise.passive.txt

echo "IX"
proverif IX.noise.active.pv > IX.noise.active.txt
proverif IX.noise.passive.pv > IX.noise.passive.txt

echo "KK1"
proverif KK1.noise.active.pv > KK1.noise.active.txt
proverif KK1.noise.passive.pv > KK1.noise.passive.txt

echo "KN"
proverif KN.noise.active.pv > KN.noise.active.txt
proverif KN.noise.passive.pv > KN.noise.passive.txt

echo "NX1"
proverif NX1.noise.active.pv > NX1.noise.active.txt
proverif NX1.noise.passive.pv > NX1.noise.passive.txt

echo "X"
proverif X.noise.active.pv > X.noise.active.txt
proverif X.noise.passive.pv > X.noise.passive.txt

echo "XX"
proverif XX.noise.active.pv > XX.noise.active.txt
proverif XX.noise.passive.pv > XX.noise.passive.txt

cd ../src/util
