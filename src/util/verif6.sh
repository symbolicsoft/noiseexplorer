#!/bin/bash
cd ../../models

echo "KK"
proverif KK.noise.active.pv > KK.noise.active.txt
proverif KK.noise.passive.pv > KK.noise.passive.txt

echo "XN"
proverif XN.noise.active.pv > XN.noise.active.txt
proverif XN.noise.passive.pv > XN.noise.passive.txt

echo "XX1"
proverif XX1.noise.active.pv > XX1.noise.active.txt
proverif XX1.noise.passive.pv > XX1.noise.passive.txt

cd ../src/util
