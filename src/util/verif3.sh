#!/bin/bash
cd ../../models

echo "N"
proverif N.noise.active.pv > N.noise.active.txt
proverif N.noise.passive.pv > N.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/N.noise --activeResults=../models/N.noise.active.txt --passiveResults=../models/N.noise.passive.txt > html/patterns/N.noise.html
cd ../models
date

echo "NN"
proverif NN.noise.active.pv > NN.noise.active.txt
proverif NN.noise.passive.pv > NN.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/NN.noise --activeResults=../models/NN.noise.active.txt --passiveResults=../models/NN.noise.passive.txt > html/patterns/NN.noise.html
cd ../models
date

echo "NK"
proverif NK.noise.active.pv > NK.noise.active.txt
proverif NK.noise.passive.pv > NK.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/NK.noise --activeResults=../models/NK.noise.active.txt --passiveResults=../models/NK.noise.passive.txt > html/patterns/NK.noise.html
cd ../models
date

echo "NK1"
proverif NK1.noise.active.pv > NK1.noise.active.txt
proverif NK1.noise.passive.pv > NK1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/NK1.noise --activeResults=../models/NK1.noise.active.txt --passiveResults=../models/NK1.noise.passive.txt > html/patterns/NK1.noise.html
cd ../models
date

echo "KX"
proverif KX.noise.active.pv > KX.noise.active.txt
proverif KX.noise.passive.pv > KX.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/KX.noise --activeResults=../models/KX.noise.active.txt --passiveResults=../models/KX.noise.passive.txt > html/patterns/KX.noise.html
cd ../models
date

echo "KX1"
proverif KX1.noise.active.pv > KX1.noise.active.txt
proverif KX1.noise.passive.pv > KX1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/KX1.noise --activeResults=../models/KX1.noise.active.txt --passiveResults=../models/KX1.noise.passive.txt > html/patterns/KX1.noise.html
cd ../models
date

echo "NX"
proverif NX.noise.active.pv > NX.noise.active.txt
proverif NX.noise.passive.pv > NX.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/NX.noise --activeResults=../models/NX.noise.active.txt --passiveResults=../models/NX.noise.passive.txt > html/patterns/NX.noise.html
cd ../models
date

cd ../src/util
