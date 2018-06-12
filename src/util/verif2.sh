#!/bin/bash
cd ../../models

echo "IX1"
proverif IX1.noise.active.pv > IX1.noise.active.txt
proverif IX1.noise.passive.pv > IX1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/IX1.noise --activeResults=../models/IX1.noise.active.txt --passiveResults=../models/IX1.noise.passive.txt > html/patterns/IX1.noise.html
cd ../models
date

echo "K"
proverif K.noise.active.pv > K.noise.active.txt
proverif K.noise.passive.pv > K.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/K.noise --activeResults=../models/K.noise.active.txt --passiveResults=../models/K.noise.passive.txt > html/patterns/K.noise.html
cd ../models
date

echo "K1K"
proverif K1K.noise.active.pv > K1K.noise.active.txt
proverif K1K.noise.passive.pv > K1K.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/K1K.noise --activeResults=../models/K1K.noise.active.txt --passiveResults=../models/K1K.noise.passive.txt > html/patterns/K1K.noise.html
cd ../models
date

echo "K1K1"
proverif K1K1.noise.active.pv > K1K1.noise.active.txt
proverif K1K1.noise.passive.pv > K1K1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/K1K1.noise --activeResults=../models/K1K1.noise.active.txt --passiveResults=../models/K1K1.noise.passive.txt > html/patterns/K1K1.noise.html
cd ../models
date

echo "K1N"
proverif K1N.noise.active.pv > K1N.noise.active.txt
proverif K1N.noise.passive.pv > K1N.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/K1N.noise --activeResults=../models/K1N.noise.active.txt --passiveResults=../models/K1N.noise.passive.txt > html/patterns/K1N.noise.html
cd ../models
date

echo "K1X"
proverif K1X.noise.active.pv > K1X.noise.active.txt
proverif K1X.noise.passive.pv > K1X.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/K1X.noise --activeResults=../models/K1X.noise.active.txt --passiveResults=../models/K1X.noise.passive.txt > html/patterns/K1X.noise.html
cd ../models
date

echo "K1X1"
proverif K1X1.noise.active.pv > K1X1.noise.active.txt
proverif K1X1.noise.passive.pv > K1X1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/K1X1.noise --activeResults=../models/K1X1.noise.active.txt --passiveResults=../models/K1X1.noise.passive.txt > html/patterns/K1X1.noise.html
cd ../models
date

cd ../src/util
