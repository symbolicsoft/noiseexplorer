let genReady = {
	pv: {
		active: false,
		passive: false
	},
	go: false,
	rs: false
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
	return pv;
};

let goRender = (patternInput, parsedPattern, go) => {
	let parsedGo = NOISE2GO.parse(parsedPattern);
	go[0] = go[0].replace('/* $NOISE2GO_N$ */', `/*\n${patternInput}\n*/`);
	go[5] = go[5].replace('/* $NOISE2GO_I$ */', parsedGo.i);
	go[5] = go[5].replace('/* $NOISE2GO_W$ */', parsedGo.w);
	go[5] = go[5].replace('/* $NOISE2GO_R$ */', parsedGo.r);
	go[6] = go[6].replace('/* $NOISE2GO_P$ */', parsedGo.p);
	return go;
};

let rsRender = (patternInput, parsedPattern, rs) => {
	let parsedRs = NOISE2RS.parse(parsedPattern);
	rs[0] = rs[0].replace('/* $NOISE2RS_N$ */', `/*\n${patternInput}\n*/`);
	rs[5] = rs[5].replace('/* $NOISE2RS_I$ */', parsedRs.i);
	rs[5] = rs[5].replace('/* $NOISE2RS_W$ */', parsedRs.w);
	rs[5] = rs[5].replace('/* $NOISE2RS_R$ */', parsedRs.r);
	rs[6] = rs[6].replace('/* $NOISE2RS_P$ */', parsedRs.p);
	return rs;
};

let getPv = (patternInput, parsedPattern, passive, cb) => {
	let pvTemplates = [
		'0params',
		'1types',
		'2consts',
		'3utils',
		'4prims',
		'5state',
		'6channels',
		'7queries',
		'8processes'
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
				let output = pvRender(patternInput, parsedPattern, passive, pv); 
				cb(output.join('\n'));
			}
		};
		xhr.send();
	});
};

let getGo = (patternInput, parsedPattern, cb) => {
	let goTemplates = [
		'0params',
		'1types',
		'2consts',
		'3utils',
		'4prims',
		'5state',
		'6processes'
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
				let output = goRender(patternInput, parsedPattern, go);
				cb(output.join('\n'));
			}
		};
		xhr.send();
	});
};

let getRs = (patternInput, parsedPattern, cb) => {
	let rsTemplates = [
		'0params',
		'1types',
		'2consts',
		'3utils',
		'4prims',
		'5state',
		'6processes',
		'7error'
	];
	let rs = ['', '', '', '', '', '', '', ''];
	rsTemplates.forEach((templateFile, i) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `/res/rs/${templateFile}.rs`);
		xhr.onreadystatechange = () => {
			if (
				(xhr.readyState !== 4) ||
				(xhr.status !== 200)
			) {
				return false;
			}
			rs[i] = xhr.responseText;
			let full = 0;
			rs.forEach((slot) => {
				slot.length? full++ : full;
			});
			if (full === rs.length) {
				let output = rsRender(patternInput, parsedPattern, rs);
				cb(output);
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

let rsGen = (patternInput, aId, autoClick) => {
	let parsedPattern = {};
	if (genReady.rs) {
		return true;
	}
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		alert('Please first ensure that your Noise pattern is valid.');
		return false;
	}
	getRs(patternInput, parsedPattern, (rs) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `/res/rs/Cargo.toml`);
		xhr.onreadystatechange = () => {
			if (
				(xhr.readyState !== 4) ||
				(xhr.status !== 200)
			) {
				return false;
			}
			let cargo = xhr.responseText
				.replace('$NOISE2RS_N$', parsedPattern.name.toLowerCase());
			let zip = new JSZip();
			let src = zip.folder('src');
			zip.file('Cargo.toml', cargo);
			src.file('lib.rs', rs[0]);
			src.file('types.rs', rs[1]);
			src.file('consts.rs', rs[2]);
			src.file('macros.rs', rs[3]);
			src.file('prims.rs', rs[4]);
			src.file('state.rs', rs[5]);
			src.file('noisesession.rs', rs[6]);
			src.file('error.rs', rs[7]);
			zip.generateAsync({
				type:'blob'
			}).then((blob) => {
				let rsBlob = window.URL.createObjectURL(blob);
				genReady.rs = true;
				$(aId).href = rsBlob;
				$(aId).download = `${parsedPattern.name}.noise.rs.zip`;
				autoClick? $(aId).click() : false;
			});
		};
		xhr.send();
	});
	return false;
};

