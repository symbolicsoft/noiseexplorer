let genReady = {
	pv: {
		active: false,
		passive: false
	},
	go: false,
	rs: false,
	wasm: false
};

let $ = (id) => { return document.getElementById(id) };

let getArrows = (parsedPattern) => {
	let renderData = NOISEREADER.render(
		parsedPattern, [], [], [], []
	);
	return renderData.arrowSvg;
};

let pvRender = (patternInput, parsedPattern, passive, pv, cb) => {
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
	cb(pv.join('\n'));
};

let goRender = (patternInput, parsedPattern, go) => {
	let parsedGo = NOISE2GO.parse(parsedPattern);
	fetch('/res/js/versions.json').then(response => {
		if (!response.ok) {
			throw new Error("HTTP error " + response.status);
		}
		return response.json();
	}).then(json => {
		go[0] = go[0].replace('/* $NOISE2GO_N$ */', `/*\n${patternInput}\n*/`);
		go[0] = go[0].replace('/* $NOISE2GO_V$ */', `${json.major_go}.${json.minor_go}.${json.patch_go}`);
		go[5] = go[5].replace('/* $NOISE2GO_I$ */', parsedGo.i);
		go[5] = go[5].replace('/* $NOISE2GO_W$ */', parsedGo.w);
		go[5] = go[5].replace('/* $NOISE2GO_R$ */', parsedGo.r);
		go[6] = go[6].replace('/* $NOISE2GO_P$ */', parsedGo.p);
		cb(go);
	});
};

let rsRender = (patternInput, parsedPattern, rs, cb) => {
	let parsedRs = NOISE2RS.parse(parsedPattern);
	fetch('/res/js/versions.json').then(response => {
		if (!response.ok) {
			throw new Error("HTTP error " + response.status);
		}
		return response.json();
	}).then(json => {
		rs[0] = rs[0].replace('/* $NOISE2RS_N$ */', `/*\n${patternInput}\n*/`);
		rs[1] = rs[1].replace(/\$NOISE2RS_N\$/g, parsedPattern.name.toLowerCase());
		rs[5] = rs[5].replace('/* $NOISE2RS_I$ */', parsedRs.i);
		rs[5] = rs[5].replace('/* $NOISE2RS_W$ */', parsedRs.w);
		rs[5] = rs[5].replace('/* $NOISE2RS_R$ */', parsedRs.r);
		rs[6] = rs[6].replace('/* $NOISE2RS_P$ */', parsedRs.p);
		rs[9] = rs[9].replace(/\$NOISE2RS_N\$/g, parsedPattern.name.toLowerCase());
		rs[9] = rs[9].replace(/\$NOISE2RS_V\$/g, `${json.major_rust}.${json.minor_rust}.${json.patch_rust}`);
		cb(rs);
	});
};

let wasmRender = (patternInput, parsedPattern, wasm, cb) => {
	let parsedWasm = NOISE2WASM.parse(parsedPattern);
	fetch('/res/js/versions.json').then(response => {
		if (!response.ok) {
			throw new Error("HTTP error " + response.status);
		}
		return response.json();
	}).then(json => {
		wasm[0] = wasm[0].replace('/* $NOISE2WASM_N$ */', `/*\n${patternInput}\n*/`);
		wasm[5] = wasm[5].replace('/* $NOISE2WASM_I$ */', parsedWasm.i);
		wasm[5] = wasm[5].replace('/* $NOISE2WASM_W$ */', parsedWasm.w);
		wasm[5] = wasm[5].replace('/* $NOISE2WASM_R$ */', parsedWasm.r);
		wasm[6] = wasm[6].replace('/* $NOISE2WASM_P$ */', parsedWasm.p);
		wasm[9] = wasm[9].replace(/\$NOISE2WASM_N\$/g, parsedPattern.name.toLowerCase());
		wasm[9] = wasm[9].replace(/\$NOISE2WASM_V\$/g, `${json.major_wasm}.${json.minor_wasm}.${json.patch_wasm}`);
		wasm[10] = wasm[10].replace(/\$NOISE2WASM_N\$/g, parsedPattern.name.toLowerCase());
		wasm[11] = wasm[11].replace(/\$NOISE2WASM_N\$/g, parsedPattern.name.toLowerCase());
		wasm[11] = wasm[11].replace(/\$NOISE2WASM_V\$/g, `${json.major_wasm}.${json.minor_wasm}.${json.patch_wasm}`);
		cb(wasm);
	});
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
				pvRender(patternInput, parsedPattern, passive, pv, cb); 
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
				goRender(patternInput, parsedPattern, go, cb);
			}
		};
		xhr.send();
	});
};

let getRs = (patternInput, parsedPattern, cb) => {
	let rsTemplates = [
		'0params.rs',
		'1types.rs',
		'2consts.rs',
		'3utils.rs',
		'4prims.rs',
		'5state.rs',
		'6processes.rs',
		'7error.rs',
		'8macros.rs',
		'9Cargo.toml',
	];
	let rs = ['', '', '', '', '', '', '', '', '', ''];
	rsTemplates.forEach((templateFile, i) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `/res/rs/${templateFile}`);
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
				rsRender(patternInput, parsedPattern, rs, cb);
			}
		};
		xhr.send();
	});
};

let getWasm = (patternInput, parsedPattern, cb) => {
	let wasmTemplates = [
		'0params.rs',
		'1types.rs',
		'2consts.rs',
		'3utils.rs',
		'4prims.rs',
		'5state.rs',
		'6processes.rs',
		'7error.rs',
		'8macros.rs',
		'9Cargo.toml',
		'10Makefile.m',
		'11README.md'
	];
	let wasm = ['', '', '', '', '', '', '', '', '', '', '', ''];
	wasmTemplates.forEach((templateFile, i) => {
		let xhr = new XMLHttpRequest();
		xhr.open('GET', `/res/wasm/${templateFile}`);
		xhr.onreadystatechange = () => {
			if (
				(xhr.readyState !== 4) ||
				(xhr.status !== 200)
			) {
				return false;
			}
			wasm[i] = xhr.responseText;
			let full = 0;
			wasm.forEach((slot) => {
				slot.length? full++ : full;
			});
			if (full === wasm.length) {
				wasmRender(patternInput, parsedPattern, wasm, cb);
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
	$('rsLink').href = '#';
	$('wasmLink').href = '#';
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		$('patternInputParseStatus').innerText = e.toString().toLowerCase();
		$('patternInput').classList.add('parseInvalid');
		$('patternInputParseStatus').classList.add('parseInvalid');
		$('pvActiveLink').classList.add('parseInvalid');
		$('pvPassiveLink').classList.add('parseInvalid');
		$('goLink').classList.add('parseInvalid');
		$('rsLink').classList.add('parseInvalid');
		$('wasmLink').classList.add('parseInvalid');
		return false;
	}
	let arrowSvg = getArrows(parsedPattern);
	$('patternInputParseStatus').innerText = 'parsing completed successfully.';
	$('patternInput').classList.remove('parseInvalid');
	$('patternInputParseStatus').classList.remove('parseInvalid');
	$('pvActiveLink').classList.remove('parseInvalid');
	$('pvPassiveLink').classList.remove('parseInvalid');
	$('goLink').classList.remove('parseInvalid');
	$('rsLink').classList.remove('parseInvalid');
	$('wasmLink').classList.remove('parseInvalid');
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
			let zip = new JSZip();
			let src = zip.folder('src');
			src.file('lib.rs', rs[0]);
			src.file('types.rs', rs[1]);
			src.file('consts.rs', rs[2]);
			src.file('utils.rs', rs[3]);
			src.file('prims.rs', rs[4]);
			src.file('state.rs', rs[5]);
			src.file('noisesession.rs', rs[6]);
			src.file('error.rs', rs[7]);
			src.file('macros.rs', rs[8]);
			zip.file('Cargo.toml', rs[9]);
			zip.generateAsync({
				type:'blob'
			}).then((blob) => {
				let rsBlob = window.URL.createObjectURL(blob);
				genReady.rs = true;
				$(aId).href = rsBlob;
				$(aId).download = `${parsedPattern.name}.noise.rs.zip`;
				autoClick? $(aId).click() : false;
			});
	});
	return false;
};

let wasmGen = (patternInput, aId, autoClick) => {
	let parsedPattern = {};
	if (genReady.wasm) {
		return true;
	}
	try {
		parsedPattern = peg$parse(patternInput);
	} catch (e) {
		alert('Please first ensure that your Noise pattern is valid.');
		return false;
	}
	getWasm(patternInput, parsedPattern, (wasm) => {
			let zip = new JSZip();
			let src = zip.folder('src');
			src.file('lib.rs', wasm[0]);
			src.file('types.rs', wasm[1]);
			src.file('consts.rs', wasm[2]);
			src.file('utils.rs', wasm[3]);
			src.file('prims.rs', wasm[4]);
			src.file('state.rs', wasm[5]);
			src.file('noisesession.rs', wasm[6]);
			src.file('error.rs', wasm[7]);
			src.file('macros.rs', wasm[8]);
			zip.file('Cargo.toml', wasm[9]);
			zip.file('Makefile', wasm[10]);
			zip.file('README.md', wasm[11]);
			zip.generateAsync({
				type:'blob'
			}).then((blob) => {
				let wasmBlob = window.URL.createObjectURL(blob);
				genReady.wasm = true;
				$(aId).href = wasmBlob;
				$(aId).download = `${parsedPattern.name}.noise.wasm.zip`;
				autoClick? $(aId).click() : false;
			});
	});
	return false;
};
