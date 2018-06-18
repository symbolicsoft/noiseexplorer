let startingPattern = [
	'NK:',
	'<- s',
	'...',
	'-> e, es',
	'<- e, ee',
	'->'
].join('\n  ');

let modelsReady = {
	active: false,
	passive: false
};

let $ = (id) => { return document.getElementById(id) };

let getArrows = (parsedPattern) => {
	let renderData = NOISEREADER.render(
		parsedPattern, [], [], [], []
	);
	return renderData.arrowSvg;
};

let buildModel = (patternInput, parsedPattern, passive, pv) => {
	let parsedPv = NOISE2PV.parse(parsedPattern, passive);
	pv[0] = pv[0].replace('$NOISE2PV_T$', parsedPv.t);
	pv[1] = pv[1].replace('$NOISE2PV_S$', parsedPv.s);
	pv[5] = pv[5].replace('$NOISE2PV_I$', parsedPv.i);
	pv[5] = pv[5].replace('$NOISE2PV_W$', parsedPv.w);
	pv[5] = pv[5].replace('$NOISE2PV_R$', parsedPv.r);
	pv[7] = pv[7].replace('$NOISE2PV_E$', parsedPv.e);
	pv[7] = pv[7].replace('$NOISE2PV_Q$', parsedPv.q);
	pv[8] = pv[8].replace('$NOISE2PV_N$', patternInput);
	pv[8] = pv[8].replace('$NOISE2PV_G$', parsedPv.g);
	pv[8] = pv[8].replace('$NOISE2PV_A$', parsedPv.a);
	pv[8] = pv[8].replace('$NOISE2PV_B$', parsedPv.b);
	pv[8] = pv[8].replace('$NOISE2PV_K$', parsedPv.k);
	pv[8] = pv[8].replace('$NOISE2PV_P$', parsedPv.p);
	return pv.join('\n');
}

let getPvModel = (patternInput, parsedPattern, passive, cb) => {
	let pvTemplates = [
		'1params', '2types', '3consts',
		'4utils', '5prims', '6state',
		'7channels', '8queries', '9processes'
	];
	let pv = ['', '', '', '', '', '', '', '', ''];
	pvTemplates.forEach((templateFile, i) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `res/pv/${templateFile}.pv`);
		xhr.onreadystatechange = () => {
			if (
				(xhr.readyState !== 4) ||
				(xhr.status !== 200)
			) {
				return false;
			}
			pv[i] = xhr.responseText;
			let full = 0;
			pv.forEach((slot) => {
				slot.length ? full++ : full;
			});
			if (full === pv.length) {
				cb(buildModel(patternInput, parsedPattern, passive, pv));
			}
		};
		xhr.send();
	});
};

let processPatternInput = (patternInput) => {
	let parsedPattern = {};
	modelsReady.active = false;
	modelsReady.passive = false;
	$('pvModelActiveLink').href = '#';
	$('pvModelPassiveLink').href = '#';
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		$('patternInputParseStatus').innerText = e.toString().toLowerCase();
		$('patternInput').classList.add('parseInvalid');
		$('patternInputParseStatus').classList.add('parseInvalid');
		$('pvModelActiveLink').classList.add('parseInvalid');
		$('pvModelPassiveLink').classList.add('parseInvalid');
		return false;
	}
	let arrowSvg = getArrows(parsedPattern);
	$('patternInputParseStatus').innerText = 'parsing completed successfully.';
	$('patternInput').classList.remove('parseInvalid');
	$('patternInputParseStatus').classList.remove('parseInvalid');
	$('pvModelActiveLink').classList.remove('parseInvalid');
	$('pvModelPassiveLink').classList.remove('parseInvalid');
	$('patternName').innerText = parsedPattern.name;
	$('patternArrows').innerHTML = arrowSvg;
	return true;
};

let processPatternKeyUp = (key) => {
	if (key === 'Enter') {
		$('patternInput').value += '  ';
	}
};

let pvModelGen = (patternInput, attacker, aId) => {
	let parsedPattern = {};
	if (modelsReady[attacker]) {
		return true;
	}
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		alert('Please first ensure that your Noise pattern is valid.');
		return false;
	}
	getPvModel(patternInput, parsedPattern, false, (pv) => {
		let data = new Blob([pv], { type: 'text/plain' });
		let pvModel = window.URL.createObjectURL(data);
		modelsReady[attacker] = true;
		$(aId).href = pvModel;
		$(aId).download = `${parsedPattern.name}.${attacker}.pv`;
		$(aId).click();
	});
	return false;
};

window.addEventListener('load', () => {
	processPatternInput($('patternInput').value);
	$('patternInput').addEventListener('input', (event) => {
		processPatternInput($('patternInput').value);
	});
	$('patternInput').addEventListener('keyup', (event) => {
		processPatternKeyUp(event.key);
	});
	$('pvModelActiveLink').addEventListener('click', (event) => {
		pvModelGen($('patternInput').value, 'active', 'pvModelActiveLink');
	});
	$('pvModelPassiveLink').addEventListener('click', (event) => {
		pvModelGen($('patternInput').value, 'passive', 'pvModelPassiveLink');
	});
	$('patternInput').value = '';
	$('patternInput').focus();
	processPatternInput('');
	let c = 0;
	let o = 250;
	while (c < startingPattern.length) {
		setTimeout((i) => {
			$('patternInput').value += startingPattern[i];
			processPatternInput($('patternInput').value);
		}, o, c);
		c = c + 1;
		o = o + 50;
	}
});