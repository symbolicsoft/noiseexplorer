#!/bin/bash
cd ../../models

echo "X1K"
proverif X1K.noise.active.pv > X1K.noise.active.txt
proverif X1K.noise.passive.pv > X1K.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/X1K.noise --activeResults=../models/X1K.noise.active.txt --passiveResults=../models/X1K.noise.passive.txt > html/patterns/X1K.noise.html
cd ../models
date

echo "X1K1"
proverif X1K1.noise.active.pv > X1K1.noise.active.txt
proverif X1K1.noise.passive.pv > X1K1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/X1K1.noise --activeResults=../models/X1K1.noise.active.txt --passiveResults=../models/X1K1.noise.passive.txt > html/patterns/X1K1.noise.html
cd ../models
date

echo "X1N"
proverif X1N.noise.active.pv > X1N.noise.active.txt
proverif X1N.noise.passive.pv > X1N.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/X1N.noise --activeResults=../models/X1N.noise.active.txt --passiveResults=../models/X1N.noise.passive.txt > html/patterns/X1N.noise.html
cd ../models
date

echo "X1X"
proverif X1X.noise.active.pv > X1X.noise.active.txt
proverif X1X.noise.passive.pv > X1X.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/X1X.noise --activeResults=../models/X1X.noise.active.txt --passiveResults=../models/X1X.noise.passive.txt > html/patterns/X1X.noise.html
cd ../models
date

echo "X1X1"
proverif X1X1.noise.active.pv > X1X1.noise.active.txt
proverif X1X1.noise.passive.pv > X1X1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/X1X1.noise --activeResults=../models/X1X1.noise.active.txt --passiveResults=../models/X1X1.noise.passive.txt > html/patterns/X1X1.noise.html
cd ../models
date

echo "XK"
proverif XK.noise.active.pv > XK.noise.active.txt
proverif XK.noise.passive.pv > XK.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/XK.noise --activeResults=../models/XK.noise.active.txt --passiveResults=../models/XK.noise.passive.txt > html/patterns/XK.noise.html
cd ../models
date

cd ../src/util
