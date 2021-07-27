dependencies:
	@/bin/echo -n "[NoiseExplorer] Installing dependencies..."
	@npm install --save pegjs conventional-commits-parser 
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

wasm:
	@cargo install wasm-pack
	@cd util && bash genWasmBins.sh

tests:
	@cd util && bash genTests.sh

html:
	@cd util && bash genHtml.sh

clean:
	@/bin/echo -n "[NoiseExplorer] Cleaning up... "
	@rm -f parser/noiseParser.js
	@rm -rf ../implementations/rs/target
	@rm -rf ../implementations/rs/*/target
	@rm -f ../implementations/rs/*/Cargo.lock
	@rm -rf ../implementations/wasm/target
	@rm -rf ../implementations/wasm/*/target
	@rm -f ../implementations/wasm/*/Cargo.lock
	@/bin/echo " OK."

.PHONY: dependencies parser models implementations wasm tests html clean
