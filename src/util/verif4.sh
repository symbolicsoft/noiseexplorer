#!/bin/bash
cd ../../models

echo "X1K"
proverif X1K.noise.active.pv > X1K.noise.active.txt
proverif X1K.noise.passive.pv > X1K.noise.passive.txt

echo "X1K1"
proverif X1K1.noise.active.pv > X1K1.noise.active.txt
proverif X1K1.noise.passive.pv > X1K1.noise.passive.txt

echo "X1N"
proverif X1N.noise.active.pv > X1N.noise.active.txt
proverif X1N.noise.passive.pv > X1N.noise.passive.txt

echo "X1X"
proverif X1X.noise.active.pv > X1X.noise.active.txt
proverif X1X.noise.passive.pv > X1X.noise.passive.txt

echo "X1X1"
proverif X1X1.noise.active.pv > X1X1.noise.active.txt
proverif X1X1.noise.passive.pv > X1X1.noise.passive.txt

echo "XK"
proverif XK.noise.active.pv > XK.noise.active.txt
proverif XK.noise.passive.pv > XK.noise.passive.txt

echo "XK1"
proverif XK1.noise.active.pv > XK1.noise.active.txt
proverif XK1.noise.passive.pv > XK1.noise.passive.txt

echo "XN"
proverif XN.noise.active.pv > XN.noise.active.txt
proverif XN.noise.passive.pv > XN.noise.passive.txt

echo "XX"
proverif XX.noise.active.pv > XX.noise.active.txt
proverif XX.noise.passive.pv > XX.noise.passive.txt

echo "XX1"
proverif XX1.noise.active.pv > XX1.noise.active.txt
proverif XX1.noise.passive.pv > XX1.noise.passive.txt

cd ../src/util
