dependencies:
	@echo -n "[NoiseExplorer] Installing dependencies..."
	@npm install -g pegjs
	@npm install
	@echo " OK."

parser:
	@echo -n "[NoiseExplorer] Generating NoiseParser..."
	@rm -f parser/noiseParser.js
	@pegjs -o parser/noiseParser.js parser/noiseParser.pegjs
	@echo " OK."

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
	@echo -n "[NoiseExplorer] Cleaning up... "
	@rm -f parser/noiseParser.js
	@rm -rf ../implementations/rs/*/target
	@rm -f ../implementations/rs/*/Cargo.lock
	@echo " OK."

.PHONY: dependencies parser models implementations tests html clean
