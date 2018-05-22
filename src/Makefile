dependencies:
	@echo -n "[NoiseExplorer] Installing dependencies... "
	@sudo npm install -g pegjs
	@npm install
	@echo "OK."

parser:
	@echo -n "[NoiseExplorer] Generating NoiseParser... "
	@rm -f parser/noiseParser.js
	@pegjs -o parser/noiseParser.js parser/noiseParser.pegjs
	@echo "OK."

models:
	@echo -n "[NoiseExplorer] Generating models... "
	@rm -f parser/noiseParser.js
	@pegjs -o parser/noiseParser.js parser/noiseParser.pegjs
	@cd util && bash genModels.sh
	@echo "OK."

clean:
	@echo -n "[NoiseExplorer] Cleaning up... "
	@rm -f parser/noiseParser.js
	@echo "OK."

.PHONY: dependencies parser models clean
