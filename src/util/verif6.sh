#!/bin/bash
cd ../../models

echo "KK"
proverif KK.noise.active.pv > KK.noise.active.txt
proverif KK.noise.passive.pv > KK.noise.passive.txt
date

echo "XN"
proverif XN.noise.active.pv > XN.noise.active.txt
proverif XN.noise.passive.pv > XN.noise.passive.txt
date

echo "XX1"
proverif XX1.noise.active.pv > XX1.noise.active.txt
proverif XX1.noise.passive.pv > XX1.noise.passive.txt
date

echo "IK1"
proverif IK1.noise.active.pv > IK1.noise.active.txt
proverif IK1.noise.passive.pv > IK1.noise.passive.txt
date

echo "XK1"
proverif XK1.noise.active.pv > XK1.noise.active.txt
proverif XK1.noise.passive.pv > XK1.noise.passive.txt
date

cd ../src/util
