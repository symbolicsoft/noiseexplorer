dependencies:
	@/bin/echo -n "[NoiseExplorer] Installing dependencies..."
	@npm install -g pegjs
	@npm install
	@/bin/echo " OK."

parser:
	@/bin/echo -n "[NoiseExplorer] Generating NoiseParser..."
	@rm -f parser/noiseParser.js
	@pegjs -o parser/noiseParser.js parser/noiseParser.pegjs
	@/bin/echo " OK."

models:
	@rm -f parser/noiseParser.js
	@pegjs -o parser/noiseParser.js parser/noiseParser.pegjs
	@cd util && bash genModels.sh

implementations:
	@rm -f parser/noiseParser.js
	@pegjs -o parser/noiseParser.js parser/noiseParser.pegjs
	@cd util && bash genImplementations.sh

tests:
	@cd util && bash genTests.sh

html:
	@cd util && bash genHtml.sh

clean:
	@/bin/echo -n "[NoiseExplorer] Cleaning up... "
	@rm -f parser/noiseParser.js
	@rm -rf ../implementations/rs/*/target
	@rm -f ../implementations/rs/*/Cargo.lock
	@/bin/echo " OK."

.PHONY: dependencies parser models implementations tests html clean
