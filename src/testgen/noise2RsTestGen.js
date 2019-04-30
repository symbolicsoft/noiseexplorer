const NOISE2RSTESTGEN = {
	generate: () => {}
};

const gen = (
	json, protocolName,
	initPrologue, initStaticSk, initEphemeralPk, initRemoteStaticPk,
	respRemoteStaticPk, respStaticSk, respEphemeralPk,
	psk, messages
) => {
	let abc = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
	let rsTestCode = [];
	let lastLine = [];
	let initInit = `\nlet mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologue.clone(), init_static_kp`;
	let initResp = `let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologue, resp_static_kp`;
	let eph = [``, ``];
	if (initEphemeralPk.length > 0) {
		eph[0] = `if let Ok(initiator_ephemeral_private) = PrivateKey::from_str("${initEphemeralPk}") {\nif let Ok(init_ephemeral_kp) = Keypair::from_private_key(initiator_ephemeral_private) {\ninitiator_session.set_ephemeral_keypair(init_ephemeral_kp);`;
		lastLine.push(`}`);
		lastLine.push(`}`);
	}
	if (respEphemeralPk.length > 0) {
		eph[1] = `if let Ok(responder_ephemeral_private) = PrivateKey::from_str("${initPrologue}") {\nif let Ok(responder_ephemeral_kp) = Keypair::from_private_key(responder_ephemeral_private) {\nresponder_session.set_ephemeral_keypair(responder_ephemeral_kp);`;
		lastLine.push(`}`);
		lastLine.push(`}`);
	}
	rsTestCode.push(`if let Ok(prologue) = Message::from_str("${initPrologue}") {`);
	if (initStaticSk.length == 0) {
		rsTestCode.push(`if let Ok(init_static_private) = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001") {`);
	} else {
		rsTestCode.push(`if let Ok(init_static_private) = PrivateKey::from_str("${initStaticSk}") {`);
	}
	if (respStaticSk.length == 0) {
		rsTestCode.push(`if let Ok(resp_static_private) = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001") {`);
	} else {
		rsTestCode.push(`if let Ok(resp_static_private) = PrivateKey::from_str("${respStaticSk}") {`);
	}
	if (initRemoteStaticPk.length > 0) {
		rsTestCode.push(`if let Ok(resp_static_public) = resp_static_private.generate_public_key() { `);
		lastLine.push(`}`);
		initInit = `${initInit}, resp_static_public`;
	} else {
		initInit = `${initInit}, PublicKey::empty()`;
	}
	if (respRemoteStaticPk.length > 0) {
		rsTestCode.push(`if let Ok(init_static_public_key) = init_static_private.generate_public_key() {`);
		lastLine.push(`}`);
		initResp = `${initResp}, init_static_public_key`;
	} else {
		initResp = `${initResp}, PublicKey::empty()`;
	}
	rsTestCode.push(`if let Ok(init_static_kp) = Keypair::from_private_key(init_static_private) {`);
	rsTestCode.push(`if let Ok(resp_static_kp) = Keypair::from_private_key(resp_static_private) {`);
	if (psk.length > 0) {
		rsTestCode.push(`if let Ok(psk) = Psk::from_str("${psk}") {`);
		lastLine.push(`}`);
		initInit = `${initInit}, psk.clone());`;
		initResp = `${initResp}, psk);`;
	} else {
		initInit = `${initInit});`;
		initResp = `${initResp});`;
	}
	rsTestCode.push([
		`${initInit}`,
		`${initResp}`
	].join('\n\t'));
	rsTestCode.push(eph[0]);
	rsTestCode.push(eph[1]);
	for (let i = 0; i < 6; i++) {
		let send = (i % 2 === 0) ? 'initiator_session' : 'responder_session';
		let recv = (i % 2 === 0) ? 'responder_session' : 'initiator_session';
		rsTestCode.push([
			`if let Ok(m${abc[i]}) = Message::from_str("${messages[i].payload}") {`,
			`if let Ok(t${abc[i]}) = Message::from_str("${messages[i].ciphertext}") {`
		].join(`\n\t`));
		rsTestCode.push([
			`if let Ok(message${abc[i]}) = ${send}.send_message(m${abc[i]}) {`,
			`if let Ok(_x) = ${recv}.recv_message(message${abc[i]}.clone()) {`
		].join('\n\t'));
	}

	for (let i = 0; i < 6; i++) {
		rsTestCode.push(`assert!(t${abc[i]} == message${abc[i]}, ${String.raw`"\n\n\nTest ${abc[i]}: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}"`}, t${abc[i]}, message${abc[i]});`);
	}
	rsTestCode.push(lastLine.join(``));
	rsTestCode.push(`}}}}}}}}}}}}}}}}}}}}}}}}}}}}}`);
	return rsTestCode.join('\n\t');
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

const generate = (json) => {
	const fs = require('fs');
	const testVectors = JSON.parse(
		fs.readFileSync('../tests/cacophony.json', 'utf-8')
	).vectors;
	for (let i = 0; i < testVectors.length; i++) {
		let tempA = testVectors[i].protocol_name.split('_');
		if (
			tempA[1] === json.name &&
			tempA[2] === '25519' &&
			testVectors[i].protocol_name.split("_")[3] === 'ChaChaPoly' &&
			testVectors[i].protocol_name.split("_")[4] == 'BLAKE2s'
		) {
			let test = assign(json, testVectors[i]);
			return test;
		}
	}
}

if (typeof (module) !== 'undefined') {
	// Node
	module.exports = {
		generate: generate
	};
} else {
	// Web
	NOISE2RSTESTGEN.generate = generate;
}