const NOISE2GOTESTGEN = {
	generate: () => {}
};


const gen = (
	protocolName,
	initPrologue, initStaticSk, initEphemeralPk, initRemoteStaticPk,
	respRemoteStaticPk, respStaticSk, respEphemeralPk,
	psk, messages
) => {
	let goTestCode = [];
	let initInit = `initiatorSession := InitSession(true, prologue, initStatic`;
	let initResp = `responderSession := InitSession(false, prologue, respStatic`;
	let eph = ["", ""];
	if (initEphemeralPk.length > 0) {
		eph[0] = `${[
			`esk, _ := hex.DecodeString("${initEphemeralPk}")`,
			`copy(e.sk[:], esk[:])`,
			`e.pk = generatePublicKey(e.sk)`].join("\n\t")}`;
	}
	if (respEphemeralPk.length > 0) {
		eph[1] = `${[
			`esk, _ := hex.DecodeString("${respEphemeralPk}")`,
			`copy(e.sk[:], esk[:])`,
			`e.pk = generatePublicKey(e.sk)`].join("\n\t")}`;
	}
	goTestCode.push(`\tprologue, _ := hex.DecodeString("${initPrologue}")`);
	goTestCode.push(`var initStatic keypair`);
	if (initStaticSk.length > 0) {
		goTestCode.push(`initStaticSk, _ := hex.DecodeString("${initStaticSk}")`);
	} else {
		goTestCode.push(`initStaticSk := emptyKey`);
	}
	goTestCode.push(`copy(initStatic.sk[:], initStaticSk[:])`);
	goTestCode.push(`initStatic.pk = generatePublicKey(initStatic.sk)`);
	goTestCode.push(`var respStatic keypair`);
	if (respStaticSk.length > 0) {
		goTestCode.push(`respStaticSk, _ := hex.DecodeString("${respStaticSk}")`);
	} else {
		goTestCode.push(`respStaticSk := emptyKey`);
	}
	goTestCode.push(`copy(respStatic.sk[:], respStaticSk[:])`);
	goTestCode.push(`respStatic.pk = generatePublicKey(respStatic.sk)`);
	if (initRemoteStaticPk.length > 0) {
		initInit = initInit + `, respStatic.pk`;
	} else {
		initInit = initInit + `, emptyKey`;
	}
	if (respRemoteStaticPk.length > 0) {
		initResp = initResp.concat(`, initStatic.pk`);
	} else {
		initResp = initResp.concat(`, emptyKey`);
	}
	if (psk.length > 0) {
		goTestCode.push(`var psk [32]byte`);
		goTestCode.push(`pskTemp, _ := hex.DecodeString("${psk}")`);
		goTestCode.push(`copy(psk[:], pskTemp[:32])`);
		initInit = initInit + `, psk)`;
		initResp = initResp + `, psk)`;
	} else {
		initInit = initInit + `)`;
		initResp = initResp + `)`;
	}
	goTestCode.push([
		`${initInit}`,
		`${initResp}`,
		`payloadA, _ := hex.DecodeString("${messages[0].payload}")`,
		`payloadB, _ := hex.DecodeString("${messages[1].payload}")`,
		`payloadC, _ := hex.DecodeString("${messages[2].payload}")`,
		`payloadD, _ := hex.DecodeString("${messages[3].payload}")`,
		`payloadE, _ := hex.DecodeString("${messages[4].payload}")`,
		`payloadF, _ := hex.DecodeString("${messages[5].payload}")`,
		`initiatorSession, messageA := SendMessage(initiatorSession, payloadA)`,
		`responderSession, _, validA := RecvMessage(responderSession, messageA)`,
		`responderSession, messageB := SendMessage(responderSession, payloadB)`,
		`initiatorSession, _, validB := RecvMessage(initiatorSession, messageB)`,
		`initiatorSession, messageC := SendMessage(initiatorSession, payloadC)`,
		`responderSession, _, validC := RecvMessage(responderSession, messageC)`,
		`responderSession, messageD := SendMessage(responderSession, payloadD)`,
		`initiatorSession, _, validD := RecvMessage(initiatorSession, messageD)`,
		`initiatorSession, messageE := SendMessage(initiatorSession, payloadE)`,
		`responderSession, _, validE := RecvMessage(responderSession, messageE)`,
		`responderSession, messageF := SendMessage(responderSession, payloadF)`,
		`initiatorSession, _, validF := RecvMessage(initiatorSession, messageF)`,
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
		`cF := hex.EncodeToString(messageF.ns) + hex.EncodeToString(messageF.ciphertext)`,
		`tA := "${messages[0].ciphertext}"`,
		`tB := "${messages[1].ciphertext}"`,
		`tC := "${messages[2].ciphertext}"`,
		`tD := "${messages[3].ciphertext}"`,
		`tE := "${messages[4].ciphertext}"`,
		`tF := "${messages[5].ciphertext}"`,
		`if tA == cA {\n\t\tprintln("Test 1: PASS")\n\t} else {\n\t\tprintln("Test 1: FAIL")\n\t\tprintln("Expected:\t", tA) \n\t\tprintln("Actual:\t\t", cA)\n\t}`,
		`if tB == cB {\n\t\tprintln("Test 2: PASS")\n\t} else {\n\t\tprintln("Test 2: FAIL")\n\t\tprintln("Expected:\t", tB) \n\t\tprintln("Actual:\t\t", cB)\n\t}`,
		`if tC == cC {\n\t\tprintln("Test 3: PASS")\n\t} else {\n\t\tprintln("Test 3: FAIL")\n\t\tprintln("Expected:\t", tC) \n\t\tprintln("Actual:\t\t", cC)\n\t}`,
		`if tD == cD {\n\t\tprintln("Test 4: PASS")\n\t} else {\n\t\tprintln("Test 4: FAIL")\n\t\tprintln("Expected:\t", tD) \n\t\tprintln("Actual:\t\t", cD)\n\t}`,
		`if tE == cE {\n\t\tprintln("Test 5: PASS")\n\t} else {\n\t\tprintln("Test 5: FAIL")\n\t\tprintln("Expected:\t", tE) \n\t\tprintln("Actual:\t\t", cE)\n\t}`,
		`if tF == cF {\n\t\tprintln("Test 6: PASS")\n\t} else {\n\t\tprintln("Test 6: FAIL")\n\t\tprintln("Expected:\t", tF) \n\t\tprintln("Actual:\t\t", cF)\n\t}`
	].join('\n\t'));
	goTestCode = `${goTestCode.join('\n\t')}`;
	return [goTestCode, eph];
}

const assign = (data) => {
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
		protocolName, prologue,
		initStaticSk, initEphemeralPk, initRemoteStaticPk,
		respRemoteStaticPk, respStaticSk, respEphemeralPk,
		psk, messages
	);
};

const generate = (code) => {
	const fs = require('fs');
	const testVectors = JSON.parse(
		fs.readFileSync('../tests/cacophony.json', 'utf-8')
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
			let tempB = assign(testVectors[i]);
			code = code.replace(`\"encoding/binary\"`, `\"encoding/binary\"\n\t\"encoding/hex\"`);
			code = code.replace(`e = generateKeypair()`, tempB[1][0])
			if (tempB[1][1] != "") {
				code = code.replace(`e = generateKeypair()`, tempB[1][1])
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