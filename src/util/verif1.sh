#!/bin/bash
cd ../../models

echo "I1K"
proverif I1K.noise.active.pv > I1K.noise.active.txt
proverif I1K.noise.passive.pv > I1K.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/I1K.noise --activeResults=../models/I1K.noise.active.txt --passiveResults=../models/I1K.noise.passive.txt > html/patterns/I1K.noise.html
cd ../models
date

echo "I1K1"
proverif I1K1.noise.active.pv > I1K1.noise.active.txt
proverif I1K1.noise.passive.pv > I1K1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/I1K1.noise --activeResults=../models/I1K1.noise.active.txt --passiveResults=../models/I1K1.noise.passive.txt > html/patterns/I1K1.noise.html
cd ../models
date

echo "I1N"
proverif I1N.noise.active.pv > I1N.noise.active.txt
proverif I1N.noise.passive.pv > I1N.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/I1N.noise --activeResults=../models/I1N.noise.active.txt --passiveResults=../models/I1N.noise.passive.txt > html/patterns/I1N.noise.html
cd ../models
date

echo "I1X"
proverif I1X.noise.active.pv > I1X.noise.active.txt
proverif I1X.noise.passive.pv > I1X.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/I1X.noise --activeResults=../models/I1X.noise.active.txt --passiveResults=../models/I1X.noise.passive.txt > html/patterns/I1X.noise.html
cd ../models
date

echo "I1X1"
proverif I1X1.noise.active.pv > I1X1.noise.active.txt
proverif I1X1.noise.passive.pv > I1X1.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/I1X1.noise --activeResults=../models/I1X1.noise.active.txt --passiveResults=../models/I1X1.noise.passive.txt > html/patterns/I1X1.noise.html
cd ../models
date

echo "IK"
proverif IK.noise.active.pv > IK.noise.active.txt
proverif IK.noise.passive.pv > IK.noise.passive.txt
cd ../src
node noiseExplorer --render --pattern=../patterns/IK.noise --activeResults=../models/IK.noise.active.txt --passiveResults=../models/IK.noise.passive.txt > html/patterns/IK.noise.html
cd ../models
date

cd ../src/util
