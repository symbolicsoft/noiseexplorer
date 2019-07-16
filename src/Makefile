dependencies:
	@/bin/echo -n "[NoiseExplorer] Installing dependencies..."
	@npm install --save pegjs conventional-commits-parser 
	@npm install
	@curl https://rustwasm.github.io/wasm-pack/installer/init.sh -sSf | sh
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

wasm:
	@cd util && bash genWasmBins.sh

tests:
	@cd util && bash genTests.sh

html:
	@cd util && bash genHtml.sh

pre-release:
	@cd util && node prep.js
	@make implementations

clean:
	@/bin/echo -n "[NoiseExplorer] Cleaning up... "
	@rm -f parser/noiseParser.js
	@rm -rf ../implementations/rs/*/target
	@rm -f ../implementations/rs/*/Cargo.lock
	@/bin/echo " OK."

.PHONY: dependencies parser models implementations wasm tests html clean
