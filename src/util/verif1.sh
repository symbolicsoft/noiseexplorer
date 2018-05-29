#!/bin/bash
cd ../../models

echo "I1K"
proverif I1K.noise.active.pv > I1K.noise.active.txt
proverif I1K.noise.passive.pv > I1K.noise.passive.txt

echo "I1K1"
proverif I1K1.noise.active.pv > I1K1.noise.active.txt
proverif I1K1.noise.passive.pv > I1K1.noise.passive.txt

echo "I1N"
proverif I1N.noise.active.pv > I1N.noise.active.txt
proverif I1N.noise.passive.pv > I1N.noise.passive.txt

echo "I1X"
proverif I1X.noise.active.pv > I1X.noise.active.txt
proverif I1X.noise.passive.pv > I1X.noise.passive.txt

echo "I1X1"
proverif I1X1.noise.active.pv > I1X1.noise.active.txt
proverif I1X1.noise.passive.pv > I1X1.noise.passive.txt

echo "IK"
proverif IK.noise.active.pv > IK.noise.active.txt
proverif IK.noise.passive.pv > IK.noise.passive.txt

echo "IK1"
proverif IK1.noise.active.pv > IK1.noise.active.txt
proverif I1K1.noise.passive.pv > IK1.noise.passive.txt

echo "IN"
proverif IN.noise.active.pv > IN.noise.active.txt
proverif IN.noise.passive.pv > IN.noise.passive.txt

echo "IX"
proverif IX.noise.active.pv > IX.noise.active.txt
proverif IX.noise.passive.pv > IX.noise.passive.txt

cd ../src/util
