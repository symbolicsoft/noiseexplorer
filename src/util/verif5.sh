#!/bin/bash
cd ../../models

echo "IN"
proverif IN.noise.active.pv > IN.noise.active.txt
proverif IN.noise.passive.pv > IN.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/IN.noise --activeResults=../models/IN.noise.active.txt --passiveResults=../models/IN.noise.passive.txt > html/patterns/IN.noise.html
cd ../models
date

echo "IX"
proverif IX.noise.active.pv > IX.noise.active.txt
proverif IX.noise.passive.pv > IX.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/IX.noise --activeResults=../models/IX.noise.active.txt --passiveResults=../models/IX.noise.passive.txt > html/patterns/IX.noise.html
cd ../models
date

echo "KK1"
proverif KK1.noise.active.pv > KK1.noise.active.txt
proverif KK1.noise.passive.pv > KK1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/KK1.noise --activeResults=../models/KK1.noise.active.txt --passiveResults=../models/KK1.noise.passive.txt > html/patterns/KK1.noise.html
cd ../models
date

echo "KN"
proverif KN.noise.active.pv > KN.noise.active.txt
proverif KN.noise.passive.pv > KN.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/KN.noise --activeResults=../models/KN.noise.active.txt --passiveResults=../models/KN.noise.passive.txt > html/patterns/KN.noise.html
cd ../models
date

echo "NX1"
proverif NX1.noise.active.pv > NX1.noise.active.txt
proverif NX1.noise.passive.pv > NX1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/NX1.noise --activeResults=../models/NX1.noise.active.txt --passiveResults=../models/NX1.noise.passive.txt > html/patterns/NX1.noise.html
cd ../models
date

echo "X"
proverif X.noise.active.pv > X.noise.active.txt
proverif X.noise.passive.pv > X.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/X.noise --activeResults=../models/X.noise.active.txt --passiveResults=../models/X.noise.passive.txt > html/patterns/X.noise.html
cd ../models
date

echo "XX"
proverif XX.noise.active.pv > XX.noise.active.txt
proverif XX.noise.passive.pv > XX.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/XX.noise --activeResults=../models/XX.noise.active.txt --passiveResults=../models/XX.noise.passive.txt > html/patterns/XX.noise.html
cd ../models
date

cd ../src/util
