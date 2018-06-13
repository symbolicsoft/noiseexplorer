const FS = require('fs');
const ARGV = require('minimist')(process.argv.slice(2));
const NOISEPARSER = require('./parser/noiseParser.js');
const NOISE2PV = require('./parser/noise2Pv.js');
const NOISEREADER = require('./parser/noiseReader.js');

const UTIL = {
	abc: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
};

const HELPTEXT = [
	'Noise Explorer version 0.3 (specification revision 34)',
	'Noise Explorer can either generate models or render results, and the parameters',
	'for either must be invoked exclusively.',
	'',
	'Model generation:',
	'--generate=(proverif|json): Specify output format.',
	'--pattern=[file]: Specify input pattern file (required).',
	'--attacker=(active|passive): Specify attacker type (default: active).',
	'',
	'Results rendering:',
	'--render=(handshake|message): Render results from ProVerif output files into HTML.',
	'--pattern=[file]: Specify input pattern file (required).',
	'--activeModel=[file]: Specify ProVerif active attacker model (required for --render=message).',
	'--activeResults=[file]: Specify active results file for --render (required).',
	'--passiveResults=[file]: Specify passive results file for --render (required).',
	'',
	'Help:',
	'--help: View this help text.'
].join('\n\t');
const ERRMSG = [];

if (
	ARGV.hasOwnProperty('help') ||
	(!ARGV.hasOwnProperty('generate') &&
		!ARGV.hasOwnProperty('render')
	) ||
	(ARGV.hasOwnProperty('generate') && (
		ARGV.hasOwnProperty('render') ||
		!ARGV.hasOwnProperty('pattern') ||
		ARGV.hasOwnProperty('activeResults') ||
		ARGV.hasOwnProperty('passiveResults') ||
		ARGV.hasOwnProperty('activeModel')
	)) ||
	(ARGV.hasOwnProperty('render') && (
		ARGV.hasOwnProperty('generate') ||
		!ARGV.hasOwnProperty('pattern') ||
		ARGV.hasOwnProperty('attacker') ||
		!ARGV.hasOwnProperty('activeResults') ||
		!ARGV.hasOwnProperty('passiveResults') ||
		((ARGV.render === 'message') &&
			!ARGV.hasOwnProperty('activeModel')
		)
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
	if (!ARGV.hasOwnProperty('attacker')) {
		ARGV.attacker = 'active';
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
		throw new Error(`Could not read from input file ${path}.`);
	}
	return result;
};

const WRITEFILE = (path, data) => {
	try {
		FS.writeFileSync(path, data);
	} catch (err) {
		throw new Error(`Could not write to output file ${path}.`);
	}
	return true;
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
	pv[1] = pv[1].replace('$NOISE2PV_S$', parsedPv.s);
	pv[5] = pv[5].replace('$NOISE2PV_I$', parsedPv.i);
	pv[5] = pv[5].replace('$NOISE2PV_W$', parsedPv.w);
	pv[5] = pv[5].replace('$NOISE2PV_R$', parsedPv.r);
	pv[7] = pv[7].replace('$NOISE2PV_E$', parsedPv.e);
	pv[7] = pv[7].replace('$NOISE2PV_Q$', parsedPv.q);
	pv[8] = pv[8].replace('$NOISE2PV_N$', pattern);
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

if (ARGV.hasOwnProperty('render')) {
	if (!(/^(handshake)|(message)$/).test(ARGV.render)) {
		throw new Error('You must specify a valid rendering output format.');
		process.exit();
	}
	if (ARGV.render === 'handshake') {
		let passive = (ARGV.attacker === 'passive');
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
		if (!FS.existsSync(`html/patterns/${json.name}`)) {
			FS.mkdirSync(`html/patterns/${json.name}`);
		}
		WRITEFILE(`html/patterns/${json.name}/index.html`, output);
		process.exit();
	} else if (ARGV.render === 'message') {
		let activeModel = READFILE(ARGV.activeModel);
		let pattern = READFILE(ARGV.pattern);
		let pvOutputActive = READFILE(ARGV.activeResults);
		let pvOutputPassive = READFILE(ARGV.passiveResults);
		let json = NOISEPARSER.parse(pattern);
		let [readResultsActive, rawResultsActive] = NOISEREADER.read(pvOutputActive);
		let [readResultsPassive, rawResultsPassive] = NOISEREADER.read(pvOutputPassive);
		json.messages.forEach((message, i) => {
			let html = NOISEREADER.renderDetailed(
				activeModel, json, i, readResultsActive, readResultsPassive,
				rawResultsActive, rawResultsPassive
			);
			let output = READFILE('html/patterns/templateDetailed.html')
				.replace(/\$NOISERENDER_T\$/g, json.name)
				.replace(/\$NOISERENDER_R\$/g, html.arrowSvg)
				.replace(/\$NOISERENDER_A\$/g, html.analysisTxt)
				.replace(/\$NOISERENDER_I\$/g, html.title);
			if (!FS.existsSync(`html/patterns/${json.name}`)) {
				FS.mkdirSync(`html/patterns/${json.name}`);
			}
			WRITEFILE(`html/patterns/${json.name}/${UTIL.abc[i].toUpperCase()}.html`, output);
		});
		process.exit();
	}
}
