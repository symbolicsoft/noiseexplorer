const NOISE2GOTESTGEN = {
	generate: () => {}
};

const gen = (
	json, protocolName,
	initPrologue, initStaticSk, initEphemeralPk, initRemoteStaticPk,
	respRemoteStaticPk, respStaticSk, respEphemeralPk,
	psk, messages
) => {
	let abc = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
	let goTestCode = [];
	let initInit = `initiatorSession := InitSession(true, prologue, initStatic`;
	let initResp = `responderSession := InitSession(false, prologue, respStatic`;
	let eph = ["", ""];
	if (initEphemeralPk.length > 0) {
		eph[0] = `${[
			`esk, _ := hex.DecodeString("${initEphemeralPk}")`,
			`copy(hs.e.private_key[:], esk[:])`,
			`hs.e.public_key = generatePublicKey(hs.e.private_key)`].join("\n\t")}`;
	}
	if (respEphemeralPk.length > 0) {
		eph[1] = `${[
			`esk, _ := hex.DecodeString("${respEphemeralPk}")`,
			`copy(hs.e.private_key[:], esk[:])`,
			`hs.e.public_key = generatePublicKey(hs.e.private_key)`].join("\n\t")}`;
	}
	goTestCode.push(`\tprologue, _ := hex.DecodeString("${initPrologue}")`);
	goTestCode.push(`var initStatic keypair`);
	if (initStaticSk.length > 0) {
		goTestCode.push(`initStaticSk, _ := hex.DecodeString("${initStaticSk}")`);
	} else {
		goTestCode.push(`initStaticSk := emptyKey`);
	}
	goTestCode.push(`copy(initStatic.private_key[:], initStaticSk[:])`);
	goTestCode.push(`initStatic.public_key = generatePublicKey(initStatic.private_key)`);
	goTestCode.push(`var respStatic keypair`);
	if (respStaticSk.length > 0) {
		goTestCode.push(`respStaticSk, _ := hex.DecodeString("${respStaticSk}")`);
	} else {
		goTestCode.push(`respStaticSk := emptyKey`);
	}
	goTestCode.push(`copy(respStatic.private_key[:], respStaticSk[:])`);
	goTestCode.push(`respStatic.public_key = generatePublicKey(respStatic.private_key)`);
	if (initRemoteStaticPk.length > 0) {
		initInit = `${initInit}, respStatic.public_key`;
	} else {
		initInit = `${initInit}, emptyKey`;
	}
	if (respRemoteStaticPk.length > 0) {
		initResp = `${initResp}, initStatic.public_key`;
	} else {
		initResp = `${initResp}, emptyKey`;
	}
	if (psk.length > 0) {
		goTestCode.push(`var psk [32]byte`);
		goTestCode.push(`pskTemp, _ := hex.DecodeString("${psk}")`);
		goTestCode.push(`copy(psk[:], pskTemp[:32])`);
		initInit = `${initInit}, psk)`;
		initResp = `${initResp}, psk)`;
	} else {
		initInit = `${initInit})`;
		initResp = `${initResp})`;
	}
	goTestCode.push([
		`${initInit}`,
		`${initResp}`
	].join('\n\t'));
	for (let i = 0; i < 6; i++) {
		let send = (i % 2 === 0) ? 'initiatorSession' : 'responderSession';
		let recv = (i % 2 === 0) ? 'responderSession' : 'initiatorSession';
		goTestCode.push([
			`payload${abc[i]}, _ := hex.DecodeString("${messages[i].payload}")`,
			`_, message${abc[i]} := SendMessage(&${send}, payload${abc[i]})`,
			`_, _, valid${abc[i]} := RecvMessage(&${recv}, &message${abc[i]})`,
			`t${abc[i]} := "${messages[i].ciphertext}"`
		].join('\n\t'));
	}
	goTestCode.push([
		`if validA && validB && validC && validD && validE && validF {`,
		`\tprintln("Sanity check PASS for ${protocolName}.")`,
		`} else {`,
		`\tprintln("Sanity check FAIL for ${protocolName}.")`,
		`}`,
		`cA := ${initEphemeralPk.length ? `hex.EncodeToString(messageA.ne[:]) + ` : ``}hex.EncodeToString(messageA.ns) + hex.EncodeToString(messageA.ciphertext)`,
		`cB := ${respEphemeralPk.length ? `hex.EncodeToString(messageB.ne[:]) + ` : ``}hex.EncodeToString(messageB.ns) + hex.EncodeToString(messageB.ciphertext)`,
		`cC := hex.EncodeToString(messageC.ns) + hex.EncodeToString(messageC.ciphertext)`,
		`cD := hex.EncodeToString(messageD.ns) + hex.EncodeToString(messageD.ciphertext)`,
		`cE := hex.EncodeToString(messageE.ns) + hex.EncodeToString(messageE.ciphertext)`,
		`cF := hex.EncodeToString(messageF.ns) + hex.EncodeToString(messageF.ciphertext)`
	].join('\n\t'));
	for (let i = 0; i < 6; i++) {
		goTestCode.push([
			`if t${abc[i]} == c${abc[i]} {`,
			`\tprintln("Test ${abc[i]}: PASS")`,
			`} else {`,
			`\tprintln("Test ${abc[i]}: FAIL")`,
			`\tprintln("Expected: ", t${abc[i]})`,
			`\tprintln("Actual:   ", c${abc[i]})`,
			`}`,
		].join('\n\t'));
	}
	goTestCode = `${goTestCode.join('\n\t')}`;
	return [goTestCode, eph];
}

const assign = (json, data) => {
	let [prologue, psk] = ['', ''];
	let [initStaticSk, initEphemeralPk, initRemoteStaticPk] = ['', '', ''];
	let [respRemoteStaticPk, respStaticSk, respEphemeralPk] = ['', '', ''];
	let messages = '';
	if (data.hasOwnProperty('protocol_name')) {
		protocolName = data.protocol_name.split('_').slice(1).join('_');
	}
	if (data.hasOwnProperty('init_prologue')) {
		prologue = data.init_prologue;
	}
	if (data.hasOwnProperty('init_psks')) {
		psk = data.init_psks[0];
	}
	if (data.hasOwnProperty('init_static')) {
		initStaticSk = data.init_static;
	}
	if (data.hasOwnProperty('init_ephemeral')) {
		initEphemeralPk = data.init_ephemeral;
	}
	if (data.hasOwnProperty('init_remote_static')) {
		initRemoteStaticPk = data.init_remote_static;
	}
	if (data.hasOwnProperty('resp_remote_static')) {
		respRemoteStaticPk = data.resp_remote_static;
	}
	if (data.hasOwnProperty('resp_static')) {
		respStaticSk = data.resp_static;
	}
	if (data.hasOwnProperty('resp_ephemeral')) {
		respEphemeralPk = data.resp_ephemeral;
	}
	messages = data.messages;
	return gen(
		json, protocolName, prologue,
		initStaticSk, initEphemeralPk, initRemoteStaticPk,
		respRemoteStaticPk, respStaticSk, respEphemeralPk,
		psk, messages
	);
};

const generate = (json, code) => {
	const fs = require('fs');
	const testVectors = JSON.parse(
		fs.readFileSync('../implementations/tests/cacophony.json', 'utf-8')
	).vectors;
	for (let i = 0; i < testVectors.length; i++) {
		let patternName = code.split('\n')[1].slice(0, -1);
		let tempA = testVectors[i].protocol_name.split('_');
		if (
			tempA[1] === patternName &&
			tempA[2] === '25519' &&
			testVectors[i].protocol_name.split("_")[3] === 'ChaChaPoly' &&
			testVectors[i].protocol_name.split("_")[4] == 'BLAKE2s'
		) {
			let tempB = assign(assign, testVectors[i]);
			code = code.replace(`"encoding/binary"`, `"encoding/binary"\n\t"encoding/hex"`);
			code = code.replace(`hs.e = generateKeypair()`, tempB[1][0])
			if (tempB[1][1] != "") {
				code = code.replace(`hs.e = generateKeypair()`, tempB[1][1])
			}
			return code.replace(`func main() {}`, `func main() {\n${tempB[0]}\n}`);
		}
	}
}

if (typeof(module) !== 'undefined') {
	// Node
	module.exports = {
		generate: generate
	};
} else {
	// Web
	NOISE2GOTESTGEN.generate = generate;
}