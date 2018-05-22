const FS = require('fs');
const ARGV = require('minimist')(process.argv.slice(2));
const NOISEPARSER = require('./parser/noiseParser.js');
const NOISE2PV = require('./parser/noise2Pv.js');
const NOISEREADER = require('./parser/noiseReader.js');

const HELPTEXT = [
	'Noise Explorer v0.2',
	'Noise Explorer can either generate models or render results, and the parameters',
	'for either must be invoked exclusively.',
	'',
	'Model generation:',
	'--generate=(proverif|json): Specify output format.',
	'--pattern=[file]: Specify input pattern file (required).',
	'--attacker=(active|passive): Specify attacker type (default: active).',
	'',
	'Results rendering:',
	'--render: Render results from ProVerif output files into HTML.',
	'--pattern=[file]: Specify input pattern file (required).',
	'--activeResults=[file]: Specify active results file for --render (required).',
	'--passiveResults=[file]: Specify passive results file for --render (required).',
	'',
	'Help:',
	'--help: View this help text.'
].join('\n\t');
const ERRMSG = [];

if (
	ARGV.hasOwnProperty('help') ||
	(
		!ARGV.hasOwnProperty('generate') &&
		!ARGV.hasOwnProperty('render')
	) ||
	(ARGV.hasOwnProperty('generate') && (
		ARGV.hasOwnProperty('render') ||
		!ARGV.hasOwnProperty('pattern') ||
		!ARGV.hasOwnProperty('attacker') ||
		ARGV.hasOwnProperty('activeResults') ||
		ARGV.hasOwnProperty('passiveResults')
	)) ||
	(ARGV.hasOwnProperty('render') && (
		ARGV.hasOwnProperty('generate') ||
		!ARGV.hasOwnProperty('pattern') ||
		ARGV.hasOwnProperty('attacker') ||
		!ARGV.hasOwnProperty('activeResults') ||
		!ARGV.hasOwnProperty('passiveResults')
	))
) {
	console.log(HELPTEXT);
	process.exit();
}

if (ARGV.hasOwnProperty('generate')) {
	if (!(/^(proverif)|(json)$/).test(ARGV.generate)) {
		throw new Error('You must specify a valid generation output format.');
		process.exit();
	}
	if (!(/^(active)|(passive)$/).test(ARGV.attacker)) {
		throw new Error('You must specify a valid attacker type.');
		process.exit();
	}
}

const READFILE = (path) => {
	let result = '';
	try {
		result += FS.readFileSync(path).toString();
	} catch (err) {
		throw new Error(`Could not read input file ${path}.`);
	}
	return result;
};

const BUILDMODEL = (pattern, parsedPv) => {
	let pv = [
		READFILE('pv/1params.pv'),
		READFILE('pv/2types.pv'),
		READFILE('pv/3consts.pv'),
		READFILE('pv/4utils.pv'),
		READFILE('pv/5prims.pv'),
		READFILE('pv/6state.pv'),
		READFILE('pv/7channels.pv'),
		READFILE('pv/8queries.pv'),
		READFILE('pv/9processes.pv')
	];
	pv[0] = pv[0].replace('$NOISE2PV_T$', parsedPv.t)
	pv[5] = pv[5].replace('$NOISE2PV_I$', parsedPv.i);
	pv[5] = pv[5].replace('$NOISE2PV_W$', parsedPv.w);
	pv[5] = pv[5].replace('$NOISE2PV_R$', parsedPv.r);
	pv[7] = pv[7].replace('$NOISE2PV_E$', parsedPv.e);
	pv[7] = pv[7].replace('$NOISE2PV_Q$', parsedPv.q);
	pv[8] = pv[8].replace('$NOISE2PV_P$', pattern);
	pv[8] = pv[8].replace('$NOISE2PV_G$', parsedPv.g);
	pv[8] = pv[8].replace('$NOISE2PV_A$', parsedPv.a);
	pv[8] = pv[8].replace('$NOISE2PV_B$', parsedPv.b);
	pv[8] = pv[8].replace('$NOISE2PV_P$', parsedPv.p);
	return pv.join('\n');
};

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
	(ARGV.generate === 'proverif')
) {
	let passive = false;
	if (ARGV.attacker === 'passive') {
		passive = true;
	}
	let pattern = READFILE(ARGV.pattern);
	let json = NOISEPARSER.parse(pattern);
	let parsedPv = NOISE2PV.parse(json, passive);
	let output = BUILDMODEL(pattern, parsedPv);
	console.log(output);
	process.exit();
}

if (
	ARGV.hasOwnProperty('render')
) {
	let passive = false;
	if (ARGV.attacker === 'passive') {
		passive = true;
	}
	let pattern = READFILE(ARGV.pattern);
	let pvOutputActive = READFILE(ARGV.activeResults);
	let pvOutputPassive = READFILE(ARGV.passiveResults);
	let json = NOISEPARSER.parse(pattern);
	let [readResultsActive, rawResultsActive] = NOISEREADER.read(pvOutputActive);
	let [readResultsPassive, rawResultsPassive] = NOISEREADER.read(pvOutputPassive);
	let html = NOISEREADER.render(
		json, readResultsActive, readResultsPassive,
		rawResultsActive, rawResultsPassive
	);
	let output = READFILE('html/patterns/template.html')
		.replace(/\$NOISERENDER_T\$/g, json.name)
		.replace(/\$NOISERENDER_H\$/g, html.offset)
		.replace(/\$NOISERENDER_R\$/g, html.arrowSvg)
		.replace(/\$NOISERENDER_A\$/g, html.analysisTxt)
		.replace(/\$NOISERENDER_D\$/g, html.rawResultsDiv);
	console.log(output);
	process.exit();
}
