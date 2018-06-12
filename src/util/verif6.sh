#!/bin/bash
cd ../../models

echo "KK"
proverif KK.noise.active.pv > KK.noise.active.txt
proverif KK.noise.passive.pv > KK.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/KK.noise --activeResults=../models/KK.noise.active.txt --passiveResults=../models/KK.noise.passive.txt > html/patterns/KK.noise.html
cd ../models
date

echo "XN"
proverif XN.noise.active.pv > XN.noise.active.txt
proverif XN.noise.passive.pv > XN.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/XN.noise --activeResults=../models/XN.noise.active.txt --passiveResults=../models/XN.noise.passive.txt > html/patterns/XN.noise.html
cd ../models
date

echo "XX1"
proverif XX1.noise.active.pv > XX1.noise.active.txt
proverif XX1.noise.passive.pv > XX1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/XX1.noise --activeResults=../models/XX1.noise.active.txt --passiveResults=../models/XX1.noise.passive.txt > html/patterns/XX1.noise.html
cd ../models
date

echo "IK1"
proverif IK1.noise.active.pv > IK1.noise.active.txt
proverif IK1.noise.passive.pv > IK1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/IK1.noise --activeResults=../models/IK1.noise.active.txt --passiveResults=../models/IK1.noise.passive.txt > html/patterns/IK1.noise.html
cd ../models
date

echo "XK1"
proverif XK1.noise.active.pv > XK1.noise.active.txt
proverif XK1.noise.passive.pv > XK1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/XK1.noise --activeResults=../models/XK1.noise.active.txt --passiveResults=../models/XK1.noise.passive.txt > html/patterns/XK1.noise.html
cd ../models
date

cd ../src/util
