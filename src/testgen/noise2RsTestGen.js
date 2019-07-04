const NOISE2RSTESTGEN = {
	generate: () => {}
};

const firstCanEncryptMessage = (json) => {
	let r = -1;
	for (let i = 0; i < json.messages.length; i++) {
		if (
			(json.messages[i].tokens.indexOf('ee') >= 0) ||
			(json.messages[i].tokens.indexOf('es') >= 0) ||
			(json.messages[i].tokens.indexOf('se') >= 0) ||
			(json.messages[i].tokens.indexOf('ss') >= 0) ||
			(json.messages[i].tokens.indexOf('psk') >= 0)
		) {
			r = i;
			break;
		}
		if (
			(json.messages[i].tokens.indexOf('e') >= 0) &&
			(json.messages[i].tokens.indexOf('psk') >= 0)
		) {
			r = i;
			break;
		}
	}
	return r;
}

const gen = (
	json, protocolName,
	initPrologue, initStaticSk, initEphemeralPk, initRemoteStaticPk,
	respRemoteStaticPk, respStaticSk, respEphemeralPk,
	psk, messages
) => {
	let abc = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
	let rsTestCode = [];
	let initInit = `\n\tlet mut initiator_session: NoiseSession = NoiseSession::init_session(true, &prologue[..], initiator_static_kp`;
	let initResp = `let mut responder_session: NoiseSession = NoiseSession::init_session(false, &prologue[..], responder_static_kp`;
	let eph = [``, ``];
	if (initEphemeralPk.length > 0) {
		eph[0] = [
			`let initiator_ephemeral_private = PrivateKey::from_str("${initEphemeralPk}").unwrap();`,
			`let initiator_ephemeral_kp = Keypair::from_private_key(initiator_ephemeral_private).unwrap();`,
			`initiator_session.set_ephemeral_keypair(initiator_ephemeral_kp);`
		].join(`\n\t`);
	}
	if (respEphemeralPk.length > 0) {
		eph[1] = [
			`let responder_ephemeral_private = PrivateKey::from_str("${respEphemeralPk}").unwrap();`,
			`let responder_ephemeral_kp = Keypair::from_private_key(responder_ephemeral_private).unwrap();`,
			`responder_session.set_ephemeral_keypair(responder_ephemeral_kp);`
		].join(`\n\t`);
	}
	rsTestCode.push(`prologue = decode_str("${initPrologue}");`);
	if (initStaticSk.length == 0) {
		rsTestCode.push(`let initiator_static_private = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();`);
	} else {
		rsTestCode.push(`let initiator_static_private = PrivateKey::from_str("${initStaticSk}").unwrap();`);
	}
	if (respStaticSk.length == 0) {
		rsTestCode.push(`let responder_static_private = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();`);
	} else {
		rsTestCode.push(`let responder_static_private = PrivateKey::from_str("${respStaticSk}").unwrap();`);
	}
	if (initRemoteStaticPk || respRemoteStaticPk) {
		if (initRemoteStaticPk) {
			rsTestCode.push(`let responder_static_public = responder_static_private.generate_public_key().unwrap();`);
			initInit = `${initInit}, Some(responder_static_public)`;
		} else {
			initInit = `${initInit}, None`;
		}
		if (respRemoteStaticPk) {
			rsTestCode.push(`let initiator_static_public_key = initiator_static_private.generate_public_key().unwrap();`);
			initResp = `${initResp}, Some(initiator_static_public_key)`;
		}
		else {
			initResp = `${initResp}, None`;
		}
	}
	rsTestCode.push(`let initiator_static_kp = Keypair::from_private_key(initiator_static_private).unwrap();`);
	rsTestCode.push(`let responder_static_kp = Keypair::from_private_key(responder_static_private).unwrap();`);
	if (psk.length > 0) {
		rsTestCode.push(`let psk = Psk::from_str("${psk}").unwrap();`);
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
		let messageLength = 0;
		let spsk = psk.length> 0 ? true : false;
		let send = (i % 2 === 0) ? 'initiator' : 'responder';
		let recv = (i % 2 === 0) ? 'responder' : 'initiator';
		if (i < json.messages.length) {
			json.messages[i].tokens.forEach(token => {
				if (token == 'e' || token == 's') {
					if ((token == 's') && ((firstCanEncryptMessage(json) >= 0) && (firstCanEncryptMessage(json) <= i) || spsk )) {
						rsTestCode.push(`message${abc[i]}.extend_from_slice(&[0u8; DHLEN+MAC_LENGTH][..]);`);
						messageLength += 48;
						spsk=false;
					} 
					else {
						rsTestCode.push(`message${abc[i]}.extend_from_slice(&[0u8; DHLEN][..]);`);
						messageLength += 32;
					}
				}
			});
		}
		if (firstCanEncryptMessage(json) <= i || (psk.length > 0) ) {
		rsTestCode.push([
			`message${abc[i]}.append(&mut decode_str("${messages[i].payload}"));`,
			`message${abc[i]}.extend_from_slice(&[0u8; MAC_LENGTH][..]);`,
			`let t${abc[i]}: Vec<u8> = decode_str("${messages[i].ciphertext}");`,
			`// message${abc[i]} length is ${16+messageLength} + payload length,`,
			`// payload starts at index ${messageLength}`,

		].join(`\n\t`));
	}
		else {
		rsTestCode.push([
			`message${abc[i]}.append(&mut decode_str("${messages[i].payload}"));`,
			`let t${abc[i]}: Vec<u8> = decode_str("${messages[i].ciphertext}");`,
			`// message${abc[i]} length is ${messageLength} + payload length,`,
			`// payload starts at index ${messageLength}`,

		].join(`\n\t`));
	}


		rsTestCode.push([
			`${send}_session.send_message(&mut message${abc[i]}[..]).unwrap();`,
			`${recv}_session.recv_message(&mut message${abc[i]}.clone()[..]).unwrap();`
		].join('\n\t'));
	}

	for (let i = 0; i < 6; i++) {
		rsTestCode.push(`assert!(t${abc[i]} == message${abc[i]}, ${String.raw`"\n\n\nTest ${abc[i]}: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}"`}, t${abc[i]}, message${abc[i]});`);
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
		fs.readFileSync('../implementations/tests/cacophony.json', 'utf-8')
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

if (typeof(module) !== 'undefined') {
	// Node
	module.exports = {
		generate: generate
	};
} else {
	// Web
	NOISE2RSTESTGEN.generate = generate;
}