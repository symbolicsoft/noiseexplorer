let genReady = {
	pv: {
		active: false,
		passive: false
	},
	go: false
};

let $ = (id) => { return document.getElementById(id) };

let getArrows = (parsedPattern) => {
	let renderData = NOISEREADER.render(
		parsedPattern, [], [], [], []
	);
	return renderData.arrowSvg;
};

let pvRender = (patternInput, parsedPattern, passive, pv) => {
	let parsedPv = NOISE2PV.parse(parsedPattern, passive);
	pv[0] = pv[0].replace('(* $NOISE2PV_T$ *)', parsedPv.t)
	pv[1] = pv[1].replace('(* $NOISE2PV_S$ *)', parsedPv.s);
	pv[5] = pv[5].replace('(* $NOISE2PV_I$ *)', parsedPv.i);
	pv[5] = pv[5].replace('(* $NOISE2PV_W$ *)', parsedPv.w);
	pv[5] = pv[5].replace('(* $NOISE2PV_R$ *)', parsedPv.r);
	pv[7] = pv[7].replace('(* $NOISE2PV_E$ *)', parsedPv.e);
	pv[7] = pv[7].replace('(* $NOISE2PV_Q$ *)', parsedPv.q);
	pv[8] = pv[8].replace('(* $NOISE2PV_N$ *)', `(*\n${patternInput}\n*)`);
	pv[8] = pv[8].replace('(* $NOISE2PV_G$ *)', parsedPv.g);
	pv[8] = pv[8].replace('(* $NOISE2PV_A$ *)', parsedPv.a);
	pv[8] = pv[8].replace('(* $NOISE2PV_B$ *)', parsedPv.b);
	pv[8] = pv[8].replace('(* $NOISE2PV_K$ *)', parsedPv.k);
	pv[8] = pv[8].replace('(* $NOISE2PV_P$ *)', parsedPv.p);
	return pv.join('\n');
};

let goRender = (patternInput, parsedPattern, go) => {
	let parsedGo = NOISE2GO.parse(parsedPattern);
	go[0] = go[0].replace('/* $NOISE2GO_N$ */', `/*\n${patternInput}\n*/`);
	go[0] = go[0].replace('/* $NOISE2GO_T$ */', parsedGo.t)
	go[1] = go[1].replace('/* $NOISE2GO_S$ */', parsedGo.s);
	go[5] = go[5].replace('/* $NOISE2GO_I$ */', parsedGo.i);
	go[5] = go[5].replace('/* $NOISE2GO_W$ */', parsedGo.w);
	go[5] = go[5].replace('/* $NOISE2GO_R$ */', parsedGo.r);
	go[6] = go[6].replace('/* $NOISE2GO_G$ */', parsedGo.g);
	go[6] = go[6].replace('/* $NOISE2GO_A$ */', parsedGo.a);
	go[6] = go[6].replace('/* $NOISE2GO_B$ */', parsedGo.b);
	go[6] = go[6].replace('/* $NOISE2GO_K$ */', parsedGo.k);
	go[6] = go[6].replace('/* $NOISE2GO_P$ */', parsedGo.p);
	return go.join('\n');
};

let getPv = (patternInput, parsedPattern, passive, cb) => {
	let pvTemplates = [
		'1params', '2types', '3consts',
		'4utils', '5prims', '6state',
		'7channels', '8queries', '9processes'
	];
	let pv = ['', '', '', '', '', '', '', '', ''];
	pvTemplates.forEach((templateFile, i) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `/res/pv/${templateFile}.pv`);
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
				slot.length? full++ : full;
			});
			if (full === pv.length) {
				cb(pvRender(patternInput, parsedPattern, passive, pv));
			}
		};
		xhr.send();
	});
};

let getGo = (patternInput, parsedPattern, cb) => {
	let goTemplates = [
		'1params', '2types', '3consts',
		'4utils', '5prims', '6state',
		'7processes'
	];
	let go = ['', '', '', '', '', '', ''];
	goTemplates.forEach((templateFile, i) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `/res/go/${templateFile}.go`);
		xhr.onreadystatechange = () => {
			if (
				(xhr.readyState !== 4) ||
				(xhr.status !== 200)
			) {
				return false;
			}
			go[i] = xhr.responseText;
			let full = 0;
			go.forEach((slot) => {
				slot.length? full++ : full;
			});
			if (full === go.length) {
				cb(goRender(patternInput, parsedPattern, go));
			}
		};
		xhr.send();
	});
};

let processPatternInput = (patternInput) => {
	let parsedPattern = {};
	genReady.pv.active = false;
	genReady.pv.passive = false;
	genReady.go = false;
	$('pvActiveLink').href = '#';
	$('pvPassiveLink').href = '#';
	$('goLink').href = '#';
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		$('patternInputParseStatus').innerText = e.toString().toLowerCase();
		$('patternInput').classList.add('parseInvalid');
		$('patternInputParseStatus').classList.add('parseInvalid');
		$('pvActiveLink').classList.add('parseInvalid');
		$('pvPassiveLink').classList.add('parseInvalid');
		$('goLink').classList.add('parseInvalid');
		return false;
	}
	let arrowSvg = getArrows(parsedPattern);
	$('patternInputParseStatus').innerText = 'parsing completed successfully.';
	$('patternInput').classList.remove('parseInvalid');
	$('patternInputParseStatus').classList.remove('parseInvalid');
	$('pvActiveLink').classList.remove('parseInvalid');
	$('pvPassiveLink').classList.remove('parseInvalid');
	$('goLink').classList.remove('parseInvalid');
	$('patternName').innerText = parsedPattern.name;
	$('patternArrows').innerHTML = arrowSvg;
	return true;
};

let processPatternKeyUp = (key) => {
	if (key === 'Enter') {
		$('patternInput').value += '  ';
	}
};

let pvGen = (patternInput, attacker, aId, autoClick) => {
	let parsedPattern = {};
	let passive = /^passive$/.test(attacker);
	if (genReady.pv[attacker]) {
		return true;
	}
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		alert('Please first ensure that your Noise pattern is valid.');
		return false;
	}
	getPv(patternInput, parsedPattern, passive, (pv) => {
		let pvBlob = window.URL.createObjectURL(
			new Blob([pv], { type: 'text/plain' })
		);
		genReady.pv[attacker] = true;
		$(aId).href = pvBlob;
		$(aId).download = `${parsedPattern.name}.noise.${attacker}.pv`;
		autoClick? $(aId).click() : false;
	});
	return false;
};

let goGen = (patternInput, aId, autoClick) => {
	let parsedPattern = {};
	if (genReady.go) {
		return true;
	}
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		alert('Please first ensure that your Noise pattern is valid.');
		return false;
	}
	getGo(patternInput, parsedPattern, (go) => {
		let goBlob = window.URL.createObjectURL(
			new Blob([go], { type: 'text/plain' })
		);
		genReady.go = true;
		$(aId).href = goBlob;
		$(aId).download = `${parsedPattern.name}.noise.go`;
		autoClick? $(aId).click() : false;
	});
	return false;
};
