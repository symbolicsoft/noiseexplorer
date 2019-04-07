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
	let initInit = `let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(init_static_a)`;
	let initResp = `let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(resp_static_private)`;
	let eph = [``, ``];
	if (initEphemeralPk.length > 0) {
		eph[0] = `initiator_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("${initEphemeralPk}")));`;
	}
	if (respEphemeralPk.length > 0) {
		eph[1] = `responder_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("${respEphemeralPk}")));`;
	}
	rsTestCode.push(`let prologueA: Message = Message::from_str("${initPrologue}");`);
	rsTestCode.push(`let prologueB: Message = Message::from_str("${initPrologue}");`);
	if (initStaticSk.length == 0) {
		initStaticSk = `PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")`;
	} else {
		initStaticSk = `PrivateKey::from_str("${initStaticSk}")`;
	}
	if (respStaticSk.length == 0) {
		respStaticSk = `PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")`;
	} else {
		respStaticSk = `PrivateKey::from_str("${respStaticSk}")`;
	}
	rsTestCode = rsTestCode.concat([
		`let init_static_a: PrivateKey = ${initStaticSk};`,
		`let resp_static_private: PrivateKey = ${respStaticSk};`
	]);
	if (initRemoteStaticPk.length > 0) {
		rsTestCode.push(`let resp_static_public: PublicKey = ${respStaticSk}.generate_public_key();`);
		initInit = `${initInit}, resp_static_public`;
	} else {
		initInit = `${initInit}, PublicKey::empty()`;
	}
	if (respRemoteStaticPk.length > 0) {
		initResp = `${initResp}, PublicKey::from_str("${respRemoteStaticPk}")`;
	} else {
		initResp = `${initResp}, PublicKey::empty()`;
	}
	if (psk.length > 0) {
		rsTestCode.push(`let pskA: Psk = Psk::from_str("${psk}");`);
		rsTestCode.push(`let pskB: Psk = Psk::from_str("${psk}");`);
		initInit = `${initInit}, pskA);`;
		initResp = `${initResp}, pskB);`;
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
			`let mut message${abc[i]}: MessageBuffer = ${send}.send_message(Message::from_str("${messages[i].payload}"));`,
			`let mut valid${abc[i]}: bool = false;`,
			`if let Some(_x) = ${recv}.recv_message(&mut message${abc[i]}) {\n\t\tvalid${abc[i]} = true;\n\t}`,
			`let t${abc[i]}: Message = Message::from_str("${messages[i].ciphertext}");`
		].join('\n\t'));
	}
	rsTestCode.push([
		`assert!(`,
		`\tvalidA && validB && validC && validD && validE && validF,`,
		`\t"Sanity check FAIL for ${protocolName}."`,
		`);`
	].join('\n\t'));
	for (let i = 0; i < 6; i++) {
		rsTestCode.push(`let mut c${abc[i]}: Vec<u8> = Vec::new();`);
		if (json.messages.length > i) {
			if (json.messages[i].tokens.indexOf('e') >= 0) {
				rsTestCode.push(`c${abc[i]}.append(&mut Vec::from(&message${abc[i]}.ne[..]));`);
			}
			if (json.messages[i].tokens.indexOf('s') >= 0) {
				rsTestCode.push(`c${abc[i]}.append(&mut message${abc[i]}.ns);`);
			}
		}
		rsTestCode.push(`c${abc[i]}.append(&mut message${abc[i]}.ciphertext);`);
	}
	for (let i = 0; i < 6; i++) {
		rsTestCode.push([
			`assert!(t${abc[i]}.as_bytes() == &c${abc[i]},`,
			`\t\t${String.raw`"\n\n\nTest ${abc[i]}: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n"`},`,
			`\t\tt${abc[i]}.as_bytes(),`,
			`\t\t&cB`,
			`\t);`
		].join(`\n`));
	}
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