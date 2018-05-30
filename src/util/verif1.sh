#!/bin/bash
cd ../../models

echo "I1K"
proverif I1K.noise.active.pv > I1K.noise.active.txt
proverif I1K.noise.passive.pv > I1K.noise.passive.txt
date

echo "I1K1"
proverif I1K1.noise.active.pv > I1K1.noise.active.txt
proverif I1K1.noise.passive.pv > I1K1.noise.passive.txt
date

echo "I1N"
proverif I1N.noise.active.pv > I1N.noise.active.txt
proverif I1N.noise.passive.pv > I1N.noise.passive.txt
date

echo "I1X"
proverif I1X.noise.active.pv > I1X.noise.active.txt
proverif I1X.noise.passive.pv > I1X.noise.passive.txt
date

echo "I1X1"
proverif I1X1.noise.active.pv > I1X1.noise.active.txt
proverif I1X1.noise.passive.pv > I1X1.noise.passive.txt
date

echo "IK"
proverif IK.noise.active.pv > IK.noise.active.txt
proverif IK.noise.passive.pv > IK.noise.passive.txt
date

cd ../src/util
