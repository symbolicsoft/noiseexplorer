#!/bin/bash
cd ../../models

echo "KK"
proverif KK.noise.active.pv > ../results/KK.noise.active.txt
proverif KK.noise.passive.pv > ../results/KK.noise.passive.txt
date

echo "XN"
proverif XN.noise.active.pv > ../results/XN.noise.active.txt
proverif XN.noise.passive.pv > ../results/XN.noise.passive.txt
date

echo "XX1"
proverif XX1.noise.active.pv > ../results/XX1.noise.active.txt
proverif XX1.noise.passive.pv > ../results/XX1.noise.passive.txt
date

echo "IK1"
proverif IK1.noise.active.pv > ../results/IK1.noise.active.txt
proverif IK1.noise.passive.pv > ../results/IK1.noise.passive.txt
date

echo "XK1"
proverif XK1.noise.active.pv > ../results/XK1.noise.active.txt
proverif XK1.noise.passive.pv > ../results/XK1.noise.passive.txt
date

cd ../src/util
