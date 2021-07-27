const FS = require('fs');
const ARGV = require('minimist')(process.argv.slice(2));
const NOISEPARSER = require('./parser/noiseParser.js');
const NOISE2PV = require('./parser/noise2Pv.js');
const NOISE2GO = require('./parser/noise2Go.js');
const NOISE2RS = require('./parser/noise2Rs.js');
const NOISE2WASM = require('./parser/noise2Wasm.js');
const NOISE2GOTESTGEN = require('./testgen/noise2GoTestGen.js');
const NOISE2RSTESTGEN = require('./testgen/noise2RsTestGen.js');
const NOISE2WASMTESTGEN = require('./testgen/noise2WasmTestGen.js');
const NOISEREADER = require('./parser/noiseReader.js');
const VER = require('./versions.json');

const UTIL = {
	abc: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
};

const HELPTEXT = [
	`Noise Explorer version ${VER.major_engine}.${VER.minor_engine}.${VER.patch_engine} (specification revision 34)`,
	'Noise Explorer has three individual modes: generation, rendering and web interface.',
	'',
	'Generation:',
	'--generate=(json|pv|go|rs|wasm): Specify output format.',
	'--pattern=[file]: Specify input pattern file (required).',
	'--attacker=(active|passive): Specify ProVerif attacker type (default: active).',
	'',
	'Rendering:',
	'--render: Render results from ProVerif output files into HTML.',
	'--pattern=[file]: Specify input pattern file (required).',
	'--activeModel=[file]: Specify ProVerif active attacker model (required).',
	'--activeResults=[file]: Specify active results file for --render (required).',
	'--passiveResults=[file]: Specify passive results file for --render (required).',
	'',
	'Web interface:',
	'--web=(port): Make Noise Explorer\'s web interface available at http://localhost:(port) (default: 8000).',
	'',
	'Help:',
	'--help: View this help text.'
].join('\n');

if (
	ARGV.hasOwnProperty('help') ||
	(!ARGV.hasOwnProperty('generate') &&
		!ARGV.hasOwnProperty('render') &&
		!ARGV.hasOwnProperty('web')
	) ||
	(ARGV.hasOwnProperty('generate') && (
		ARGV.hasOwnProperty('render') ||
		ARGV.hasOwnProperty('web') ||
		!ARGV.hasOwnProperty('pattern') ||
		ARGV.hasOwnProperty('activeResults') ||
		ARGV.hasOwnProperty('passiveResults') ||
		ARGV.hasOwnProperty('activeModel') ||
		((/^(go)|(rs)|(wasm)$/).test(ARGV.generate) &&
			ARGV.hasOwnProperty('attacker')
		) ||
		((/^(go)|(rs)|(wasm)$/).test(ARGV.generate) &&
			ARGV.hasOwnProperty('tests')
		)
	)) ||
	(ARGV.hasOwnProperty('render') && (
		ARGV.hasOwnProperty('generate') ||
		ARGV.hasOwnProperty('web') ||
		!ARGV.hasOwnProperty('pattern') ||
		ARGV.hasOwnProperty('attacker') ||
		!ARGV.hasOwnProperty('activeModel') ||
		!ARGV.hasOwnProperty('activeResults') ||
		!ARGV.hasOwnProperty('passiveResults')
	)) ||
	(ARGV.hasOwnProperty('web') && (
		ARGV.hasOwnProperty('generate') ||
		ARGV.hasOwnProperty('render') ||
		ARGV.hasOwnProperty('pattern') ||
		ARGV.hasOwnProperty('attacker') ||
		ARGV.hasOwnProperty('activeResults') ||
		ARGV.hasOwnProperty('passiveResults') ||
		ARGV.hasOwnProperty('message')
	))
) {
	console.log(HELPTEXT);
	process.exit();
}

const READFILE = (path) => {
	let result = '';
	try {
		result += FS.readFileSync(path).toString();
	} catch (err) {
		throw new Error(`[NoiseExplorer] Error: Could not read from input file ${path}.`);
	}
	return result;
};

const WRITEFILE = (path, data) => {
	try {
		FS.writeFileSync(path, data);
		console.log(`[NoiseExplorer] Output written to ${path}.`);
	} catch (err) {
		throw new Error(`[NoiseExplorer] Error: Could not write to output file ${path}.`);
	}
	return true;
};

const PVRENDER = (pattern, parsedPv) => {
	let pv = [
		READFILE('pv/0params.pv'),
		READFILE('pv/1types.pv'),
		READFILE('pv/2consts.pv'),
		READFILE('pv/3utils.pv'),
		READFILE('pv/4prims.pv'),
		READFILE('pv/5state.pv'),
		READFILE('pv/6channels.pv'),
		READFILE('pv/7queries.pv'),
		READFILE('pv/8processes.pv')
	];
	pv[0] = pv[0].replace('(* $NOISE2PV_T$ *)', parsedPv.t)
	pv[1] = pv[1].replace('(* $NOISE2PV_S$ *)', parsedPv.s);
	pv[5] = pv[5].replace('(* $NOISE2PV_I$ *)', parsedPv.i);
	pv[5] = pv[5].replace('(* $NOISE2PV_W$ *)', parsedPv.w);
	pv[5] = pv[5].replace('(* $NOISE2PV_R$ *)', parsedPv.r);
	pv[7] = pv[7].replace('(* $NOISE2PV_E$ *)', parsedPv.e);
	pv[7] = pv[7].replace('(* $NOISE2PV_Q$ *)', parsedPv.q);
	pv[8] = pv[8].replace('(* $NOISE2PV_N$ *)', `(*\n${pattern}\n*)`);
	pv[8] = pv[8].replace('(* $NOISE2PV_G$ *)', parsedPv.g);
	pv[8] = pv[8].replace('(* $NOISE2PV_A$ *)', parsedPv.a);
	pv[8] = pv[8].replace('(* $NOISE2PV_B$ *)', parsedPv.b);
	pv[8] = pv[8].replace('(* $NOISE2PV_K$ *)', parsedPv.k);
	pv[8] = pv[8].replace('(* $NOISE2PV_P$ *)', parsedPv.p);
	return pv;
};

const GORENDER = (pattern, parsedGo) => {
	let go = [
		READFILE('go/0params.go'),
		READFILE('go/1types.go'),
		READFILE('go/2consts.go'),
		READFILE('go/3utils.go'),
		READFILE('go/4prims.go'),
		READFILE('go/5state.go'),
		READFILE('go/6processes.go')
	];
	go[0] = go[0].replace('/* $NOISE2GO_N$ */', `/*\n${pattern}\n*/`);
	go[0] = go[0].replace('/* $NOISE2GO_V$ */', `${VER.major_go}.${VER.minor_go}.${VER.patch_go}`);
	go[5] = go[5].replace('/* $NOISE2GO_I$ */', parsedGo.i);
	go[5] = go[5].replace('/* $NOISE2GO_W$ */', parsedGo.w);
	go[5] = go[5].replace('/* $NOISE2GO_R$ */', parsedGo.r);
	go[6] = go[6].replace('/* $NOISE2GO_P$ */', parsedGo.p);
	return go;
};

const RSRENDER = (pattern, parsedRs) => {
	let rs = [
		READFILE('rs/0params.rs'),
		READFILE('rs/1types.rs'),
		READFILE('rs/2consts.rs'),
		READFILE('rs/3utils.rs'),
		READFILE('rs/4prims.rs'),
		READFILE('rs/5state.rs'),
		READFILE('rs/6processes.rs'),
		READFILE('rs/7error.rs'),
		READFILE('rs/8macros.rs'),
		READFILE('rs/9Cargo.toml')
	];
	rs[0] = rs[0].replace('/* $NOISE2RS_N$ */', `/*\n${pattern}\n*/`);
	rs[1] = rs[1].replace(/\$NOISE2RS_N\$/g, `${NOISEPARSER.parse(pattern).name.toLowerCase()}`);
	rs[5] = rs[5].replace('/* $NOISE2RS_I$ */', parsedRs.i);
	rs[5] = rs[5].replace('/* $NOISE2RS_W$ */', parsedRs.w);
	rs[5] = rs[5].replace('/* $NOISE2RS_R$ */', parsedRs.r);
	rs[6] = rs[6].replace('/* $NOISE2RS_P$ */', parsedRs.p);
	rs[9] = rs[9].replace(/\$NOISE2RS_N\$/g, `${NOISEPARSER.parse(pattern).name.toLowerCase()}`);
	rs[9] = rs[9].replace(/\$NOISE2RS_V\$/g, `${VER.major_rust}.${VER.minor_rust}.${VER.patch_rust}`);
	return rs;
};

const WASMRENDER = (pattern, parsedWasm) => {
	let wasm = [
		READFILE('wasm/0params.rs'),
		READFILE('wasm/1types.rs'),
		READFILE('wasm/2consts.rs'),
		READFILE('wasm/3utils.rs'),
		READFILE('wasm/4prims.rs'),
		READFILE('wasm/5state.rs'),
		READFILE('wasm/6processes.rs'),
		READFILE('wasm/7error.rs'),
		READFILE('wasm/8macros.rs'),
		READFILE('wasm/9Cargo.toml'),
		READFILE('wasm/10Makefile.m'),
		READFILE('wasm/11README.md')
	];
	wasm[0] = wasm[0].replace('/* $NOISE2WASM_N$ */', `/*\n${pattern}\n*/`);
	wasm[1] = wasm[1].replace(/\$NOISE2WASM_N\$/g, `${NOISEPARSER.parse(pattern).name.toLowerCase()}`);
	wasm[5] = wasm[5].replace('/* $NOISE2WASM_I$ */', parsedWasm.i);
	wasm[5] = wasm[5].replace('/* $NOISE2WASM_W$ */', parsedWasm.w);
	wasm[5] = wasm[5].replace('/* $NOISE2WASM_R$ */', parsedWasm.r);
	wasm[6] = wasm[6].replace('/* $NOISE2WASM_P$ */', parsedWasm.p);
	wasm[9] = wasm[9].replace(/\$NOISE2WASM_N\$/g, `${NOISEPARSER.parse(pattern).name.toLowerCase()}`);
	wasm[9] = wasm[9].replace(/\$NOISE2WASM_V\$/g, `${VER.major_wasm}.${VER.minor_wasm}.${VER.patch_wasm}`);
	wasm[10] = wasm[10].replace(/\$NOISE2WASM_N\$/g, `${NOISEPARSER.parse(pattern).name.toLowerCase()}`);
	wasm[11] = wasm[11].replace(/\$NOISE2WASM_N\$/g, `${NOISEPARSER.parse(pattern).name.toLowerCase()}`);
	wasm[11] = wasm[11].replace(/\$NOISE2WASM_V\$/g, `${VER.major_wasm}.${VER.minor_wasm}.${VER.patch_wasm}`);
	return wasm;
};

if (ARGV.hasOwnProperty('generate')) {
	if (!(/^(json)|(pv)|(go)|(rs)|(wasm)$/).test(ARGV.generate)) {
		throw new Error('[NoiseExplorer] Error: You must specify a valid generation output format.');
		process.exit();
	}
	if (!ARGV.hasOwnProperty('attacker')) {
		ARGV.attacker = 'active';
	}
	if (!(/^(active)|(passive)$/).test(ARGV.attacker)) {
		throw new Error('[NoiseExplorer] Error: You must specify a valid attacker type.');
		process.exit();
	}
}

if (
	ARGV.hasOwnProperty('generate') &&
	(ARGV.generate === 'json')
) {
	let pattern = READFILE(ARGV.pattern);
	let json = NOISEPARSER.parse(pattern);
	let output = JSON.stringify(json, null, 2);
	console.log(output);
	process.exit();
}

if (
	ARGV.hasOwnProperty('generate') &&
	(ARGV.generate === 'pv')
) {
	let passive = false;
	if (ARGV.attacker === 'passive') {
		passive = true;
	}
	let pattern = READFILE(ARGV.pattern);
	let json = NOISEPARSER.parse(pattern);
	let parsedPv = NOISE2PV.parse(json, passive);
	let output = PVRENDER(pattern, parsedPv);
	WRITEFILE(`../models/${json.name}.noise.${passive? 'passive' : 'active'}.pv`, output.join('\n'));
	process.exit();
}

if (
	ARGV.hasOwnProperty('generate') &&
	(ARGV.generate === 'go')
) {
	let pattern = READFILE(ARGV.pattern);
	let json = NOISEPARSER.parse(pattern);
	let parsedGo = NOISE2GO.parse(json);
	let output = GORENDER(pattern, parsedGo);
	let testGen = NOISE2GOTESTGEN.generate(json, output.join('\n'));
	if (!FS.existsSync(`../implementations/go`)) {
		FS.mkdirSync(`../implementations/go/`);
	}
	if (!FS.existsSync(`../implementations/go/tests`)) {
		FS.mkdirSync(`../implementations/go/tests/`);
	}
	if (!FS.existsSync(`../implementations/go/tests/${json.name}`)) {
		FS.mkdirSync(`../implementations/go/tests/${json.name}/`);
	}
	WRITEFILE(`../implementations/go/tests/${json.name}/${json.name}.noise.go`, testGen);
	WRITEFILE(`../implementations/go/${json.name}.noise.go`, output.join('\n'));
	process.exit();
}

if (
	ARGV.hasOwnProperty('generate') &&
	(ARGV.generate === 'rs')
) {
	let pattern = READFILE(ARGV.pattern);
	let json = NOISEPARSER.parse(pattern);
	let psk = '';
	json.messages.forEach((message, i) => {
		if (message.tokens.indexOf('psk') >= 0) {
			psk = ', Psk';
		}
	});
	let parsedRs = NOISE2RS.parse(json);
	let output = RSRENDER(pattern, parsedRs);

	let testGen = NOISE2RSTESTGEN.generate(json, pattern);
	let test = READFILE('rs/test.rs')
		.replace("$NOISE2RS_S$", psk)
		.replace("$NOISE2RS_T$", testGen)
		.replace(/\$NOISE2RS_N\$/g, json.name.toLowerCase());

	if (!FS.existsSync(`../implementations/rs/${json.name}`)) {
		FS.mkdirSync(`../implementations/rs/${json.name}`);
		FS.mkdirSync(`../implementations/rs/${json.name}/src`);
		FS.mkdirSync(`../implementations/rs/${json.name}/tests`);
	}
	WRITEFILE(`../implementations/rs/${json.name}/src/lib.rs`, output[0]);
	WRITEFILE(`../implementations/rs/${json.name}/src/types.rs`, output[1]);
	WRITEFILE(`../implementations/rs/${json.name}/src/consts.rs`, output[2]);
	WRITEFILE(`../implementations/rs/${json.name}/src/utils.rs`, output[3]);
	WRITEFILE(`../implementations/rs/${json.name}/src/prims.rs`, output[4]);
	WRITEFILE(`../implementations/rs/${json.name}/src/state.rs`, output[5]);
	WRITEFILE(`../implementations/rs/${json.name}/src/noisesession.rs`, output[6]);
	WRITEFILE(`../implementations/rs/${json.name}/src/error.rs`, output[7]);
	WRITEFILE(`../implementations/rs/${json.name}/src/macros.rs`, output[8]);
	WRITEFILE(`../implementations/rs/${json.name}/Cargo.toml`, output[9]);
	WRITEFILE(`../implementations/rs/${json.name}/tests/handshake.rs`, test);
	process.exit();
}

if (
	ARGV.hasOwnProperty('generate') &&
	(ARGV.generate === 'wasm')
) {
	let pattern = READFILE(ARGV.pattern);
	let json = NOISEPARSER.parse(pattern);
	let psk = '';
	json.messages.forEach((message, i) => {
		if (message.tokens.indexOf('psk') >= 0) {
			psk = ', Psk';
		}
	});
	let parsedWasm = NOISE2WASM.parse(json);
	let output = WASMRENDER(pattern, parsedWasm);
	
	
	let testGen = NOISE2WASMTESTGEN.generate(json, pattern);
	let test = READFILE('wasm/test.rs')
		.replace("$NOISE2WASM_S$", psk)
		.replace("$NOISE2WASM_T$", testGen)
		.replace(/\$NOISE2WASM_N\$/g, json.name.toLowerCase());
		
	if (!FS.existsSync(`../implementations/wasm/${json.name}`)) {
		FS.mkdirSync(`../implementations/wasm/${json.name}`);
		FS.mkdirSync(`../implementations/wasm/${json.name}/src`);
		FS.mkdirSync(`../implementations/wasm/${json.name}/tests`);
	}

	WRITEFILE(`../implementations/wasm/${json.name}/src/lib.rs`, output[0]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/types.rs`, output[1]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/consts.rs`, output[2]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/utils.rs`, output[3]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/prims.rs`, output[4]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/state.rs`, output[5]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/noisesession.rs`, output[6]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/error.rs`, output[7]);
	WRITEFILE(`../implementations/wasm/${json.name}/src/macros.rs`, output[8]);
	WRITEFILE(`../implementations/wasm/${json.name}/tests/handshake.rs`, test);
	WRITEFILE(`../implementations/wasm/${json.name}/Cargo.toml`, output[9]);
	WRITEFILE(`../implementations/wasm/${json.name}/Makefile`, output[10]);
	WRITEFILE(`../implementations/wasm/${json.name}/README.md`, output[11]);
	process.exit();
}

if (ARGV.hasOwnProperty('render')) {
	let pattern = READFILE(ARGV.pattern);
	let pvOutputActive = READFILE(ARGV.activeResults);
	let pvOutputPassive = READFILE(ARGV.passiveResults);
	let activeModel = READFILE(ARGV.activeModel);
	let json = NOISEPARSER.parse(pattern);
	let [readResultsActive, rawResultsActive] = NOISEREADER.read(pvOutputActive);
	let [readResultsPassive, rawResultsPassive] = NOISEREADER.read(pvOutputPassive);
	let html = NOISEREADER.render(
		json, readResultsActive, readResultsPassive,
		rawResultsActive, rawResultsPassive
	);
	let patternSplit = pattern.replace(/(\r\n\t|\n|\r\t)/gm, '\n').split('\n');
	let patternSplitS = '[';
	patternSplit.forEach((line) => {
		if (line.length) {
			patternSplitS = `${patternSplitS}'${line}',`;
		}
	});
	patternSplitS = `${patternSplitS.slice(0, -1)}].join('\\n')`;
	let output = READFILE('html/template.html')
		.replace(/\$NOISERENDER_T\$/g, json.name)
		.replace(/\$NOISERENDER_H\$/g, html.totalHeight)
		.replace(/\$NOISERENDER_R\$/g, html.arrowSvg)
		.replace(/\$NOISERENDER_A\$/g, html.analysisTxt)
		.replace(/\$NOISERENDER_M\$/g, patternSplitS);
	if (!FS.existsSync(`../html/patterns/${json.name}`)) {
		FS.mkdirSync(`../html/patterns/${json.name}`);
	}
	WRITEFILE(`../html/patterns/${json.name}/index.html`, output);
	json.messages.forEach((message, i) => {
		html = NOISEREADER.renderDetailed(
			activeModel, json, i, readResultsActive, readResultsPassive,
			rawResultsActive, rawResultsPassive
		);
		let output = READFILE('html/templateDetailed.html')
			.replace(/\$NOISERENDER_T\$/g, json.name)
			.replace(/\$NOISERENDER_R\$/g, html.arrowSvg)
			.replace(/\$NOISERENDER_A\$/g, html.analysisTxt)
			.replace(/\$NOISERENDER_I\$/g, html.title);
		WRITEFILE(`../html/patterns/${json.name}/${UTIL.abc[i].toUpperCase()}.html`, output);
	});
	process.exit();
}

if (ARGV.hasOwnProperty('web')) {
	let port = parseInt(ARGV.web, 10);
	if (Number.isNaN(port)) {
		port = 8000;
	}
	if ((port < 1) || (port > 65535)) {
		throw new Error('[NoiseExplorer] Error: Invalid port for web interface.');
		process.exit();
	}
	console.log(`[NoiseExplorer] Running Noise Explorer web interface on port ${port}.`);
	console.log(`[NoiseExplorer]`);
	console.log(`[NoiseExplorer] WARNING: Noise Explorer's web interface is meant for internal use only.`);
	console.log(`[NoiseExplorer]          It is not recommended to expose it to the global Internet.`);
	const HTTP = require('http');
	const PATH = require('path');
	const URL = require('url');
	HTTP.createServer((req, res) => {
		try {
			let fsPath = PATH.join(PATH.join(__dirname, '../html'), URL.parse(req.url).pathname);
			if (PATH.extname(fsPath).length === 0) {
				fsPath = PATH.join(fsPath, 'index.html');
			}
			let fileStream = FS.createReadStream(fsPath);
			fileStream.pipe(res);
			fileStream.on('open', () => {
				res.writeHead(200);
			});
			fileStream.on('error', () => {
				res.writeHead(404);
				res.end();
			});
		} catch (e) {
			res.writeHead(500);
			res.end();
		}
	}).listen(port);
}
