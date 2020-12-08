const NOISE2WASM = {
	parse: () => {}
};

(() => {

	const params = {
		attacker: 'passive'
	};

	const util = {
		emptyKey: 'EMPTY_KEY',
		emptyKeyPair: 'Keypair::new_empty()',
		abc: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i'],
	};

	const preMessagesSendStatic = (pattern) => {
		let r = false;
		pattern.preMessages.forEach((preMessage) => {
			if (
				(preMessage.dir === 'send') &&
				(/s/.test(preMessage.tokens))
			) {
				r = true;
			}
		});
		return r;
	};

	const preMessagesSendEphemeral = (pattern) => {
		let r = false;
		pattern.preMessages.forEach((preMessage) => {
			if (
				(preMessage.dir === 'send') &&
				(/e/.test(preMessage.tokens))
			) {
				r = true;
			}
		});
		return r;
	};

	const preMessagesRecvStatic = (pattern) => {
		let r = false;
		pattern.preMessages.forEach((preMessage) => {
			if (
				(preMessage.dir === 'recv') &&
				(/s/.test(preMessage.tokens))
			) {
				r = true;
			}
		});
		return r;
	};

	const preMessagesRecvEphemeral = (pattern) => {
		let r = false;
		pattern.preMessages.forEach((preMessage) => {
			if (
				(preMessage.dir === 'recv') &&
				(/e/.test(preMessage.tokens))
			) {
				r = true;
			}
		});
		return r;
	};

	const messagesSendStatic = (pattern) => {
		let r = -1;
		pattern.messages.forEach((message, i) => {
			if (
				(message.dir === 'send') &&
				(message.tokens.indexOf('s') >= 0)
			) {
				r = i;
			}
		});
		return r;
	};

	const messagesRecvStatic = (pattern) => {
		let r = -1;
		pattern.messages.forEach((message, i) => {
			if (
				(message.dir === 'recv') &&
				((message.tokens.indexOf('s') >= 0))
			) {
				r = i;
			}
		});
		return r;
	};

	const messagesPsk = (pattern) => {
		let r = -1;
		pattern.messages.forEach((message, i) => {
			if (message.tokens.indexOf('psk') >= 0) {
				r = i;
			}
		});
		return r;
	};

	const firstCanEncryptMessage = (pattern) => {
		let r = -1;
		for (let i = 0; i < pattern.messages.length; i++) {
			if (
				(pattern.messages[i].tokens.indexOf('ee') >= 0) ||
				(pattern.messages[i].tokens.indexOf('es') >= 0) ||
				(pattern.messages[i].tokens.indexOf('se') >= 0) ||
				(pattern.messages[i].tokens.indexOf('ss') >= 0) ||
				(pattern.messages[i].tokens.indexOf('psk') >= 0)
			) {
				r = i;
				break;
			}
			if (
				(pattern.messages[i].tokens.indexOf('e') >= 0) &&
				(messagesPsk(pattern) >= 0)
			) {
				r = i;
				break;
			}
		}
		return r;
	}

	const finalKeyExchangeMessage = (pattern) => {
		let r = 0;
		for (let i = 0; i < pattern.messages.length; i++) {
			let b = (
				(i < 1) ||
				(pattern.messages[i - 1].tokens.length)
			);
			let a = (
				(i === (pattern.messages.length - 1)) ||
				(!pattern.messages[i + 1].tokens.length)
			);
			let c = (pattern.messages[i].tokens.length > 0);
			if (a && b && c) {
				r = i;
				break;
			}
		};
		return r;
	};

	const typeFuns = (pattern) => {
		return [''];
	};

	const initializeFun = (pattern, initiator, suffix, rs) => {
		let preMessageTokenParsers = {
			send: {
				e: `ss.mix_hash(&self.e.get_public_key().as_bytes());`,
				s: `ss.mix_hash(&s.get_public_key().as_bytes()[..]);`,
				'e, s': `ss.mix_hash(&self.e.get_public_key().as_bytes()); ss.mix_hash(&s.get_public_key().as_bytes()[..]);`
			},
			recv: {
				e: `ss.mix_hash(&self.re.as_bytes()[..DHLEN]);`,
				s: `ss.mix_hash(&rs.as_bytes()[..]);`,
				'e, s': `ss.mix_hash(&self.re.as_bytes()[..DHLEN]); ss.mix_hash(&rs.as_bytes()[..]);`
			}
		};
		let initFun = [
			`\tpub(crate) fn initialize_${suffix}(prologue: &[u8], s: Keypair${rs?', rs: PublicKey':''}, psk: Psk) -> HandshakeState {`,
			`let protocol_name = b"Noise_${pattern.name}_25519_ChaChaPoly_BLAKE2s";`,
			`let mut ss: SymmetricState = SymmetricState::initialize_symmetric(&protocol_name[..]);`,
			`ss.mix_hash(prologue);`
		];
		if (!rs) {
			initFun.push(`let rs = PublicKey::empty();`);
		}
		pattern.preMessages.forEach((preMessage) => {
			let dir = preMessage.dir;
			if (!initiator) {
				dir = (dir === 'send') ? 'recv' : 'send';
			}
			initFun.push(preMessageTokenParsers[dir][preMessage.tokens]);
		});
		initFun.push(`HandshakeState{ss, s, e: ${util.emptyKeyPair}, rs, re: PublicKey::empty(), psk}`);
		return `${initFun.join('\n\t\t')}\n\t}`;
	};

	const initializeFuns = (pattern) => {
		return [
			initializeFun(pattern, true, 'initiator', preMessagesRecvStatic(pattern)),
			initializeFun(pattern, false, 'responder', preMessagesSendStatic(pattern))
		];
	};

	const writeMessageFun = (message, hasPsk, initiator, alreadyDh, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`self.ss.mix_key(&self.e.get_public_key().as_bytes());` : `/* No PSK, so skipping mixKey */`;
		let esInitiatorFill = initiator ?
			`self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));` : `self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));`;
		let seInitiatorFill = initiator ?
			`self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));` : `self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));`;
		let finalFill = isFinal ? [
			`let h: Hash = Hash::from_bytes(from_slice_hashlen(&self.ss.h.as_bytes()));`,
			`let (cs1, cs2) = self.ss.split();`,
			`self.ss.clear();`,
			`Ok((h, cs1, cs2))`
		] : [
			`Ok(())`
		];
		let isBeyondFinal = (message.tokens.length === 0);
		if (isBeyondFinal) {
			return ``;
		}
		let nsLength = alreadyDh ? 'DHLEN+MAC_LENGTH' : 'DHLEN';
		let writeFunDeclaration = `\tpub(crate) fn write_message_${suffix}(&mut self, in_out: &mut [u8]) -> ${isFinal? `Result<(Hash, CipherState, CipherState), NoiseError>` : `Result<(), NoiseError>`} {`;
		let messageTokenParsers = {
			e: [
				`if in_out.len() < DHLEN {`,
				`\treturn Err(NoiseError::MissingneError);`,
				`}`,
				`if self.e.is_empty() {`,
				`\tself.e = Keypair::default();`,
				`}`,
				`let (ne, in_out) = in_out.split_at_mut(DHLEN);`,
				`ne.copy_from_slice(&self.e.get_public_key().as_bytes()[..]);`,
				`self.ss.mix_hash(ne);`,
				ePskFill,
			].join(`\n\t\t`),
			s: [
				`let (ns, in_out) = in_out.split_at_mut(${nsLength});`,
				`ns[..DHLEN].copy_from_slice(&self.s.get_public_key().as_bytes()[..]);`,
				`${alreadyDh ?'self.ss.encrypt_and_hash(ns)?;':'self.ss.mix_hash(ns);'}`
			].join(`\n\t\t`),
			ee: [
				`self.ss.mix_key(&self.e.dh(&self.re.as_bytes()));`
			].join(`\n\t\t`),
			es: [
				esInitiatorFill
			].join(`\n\t\t`),
			se: [
				seInitiatorFill
			].join(`\n\t\t`),
			ss: [
				`self.ss.mix_key(&self.s.dh(&self.rs.as_bytes())[..]);`
			].join(`\n\t\t`),
			psk: [
				`self.ss.mix_key_and_hash(&self.psk.as_bytes());`
			].join(`\n\t\t`),
		};
		let writeFun = [
			writeFunDeclaration
		];
		message.tokens.forEach((token) => {
			writeFun.push(messageTokenParsers[token]);
		});
		writeFun = writeFun.concat(`${alreadyDh ?'self.ss.encrypt_and_hash(in_out)?;':'self.ss.mix_hash(in_out);'}`);
		writeFun = writeFun.concat(finalFill);
		return `${writeFun.join('\n\t\t')}\n\t}`;
	};

	const writeMessageFuns = (pattern) => {
		let writeFuns = [];
		let finalKex = finalKeyExchangeMessage(pattern);
		for (let i = 0; i < pattern.messages.length; i++) {
			let message = pattern.messages[i];
			let hasPsk = messagesPsk(pattern) >= 0;
			let initiator = (message.dir === 'send');
			let isFinal = (i === finalKex);
			let alreadyDh = (
				(firstCanEncryptMessage(pattern) >= 0) &&
				(firstCanEncryptMessage(pattern) <= i)
			);
			writeFuns.push(
				writeMessageFun(message, hasPsk, initiator, alreadyDh, isFinal, util.abc[i])
			);
			if (i > finalKex) {
				break;
			}
		}
		return writeFuns;
	};

	const readMessageFun = (message, hasPsk, initiator, alreadyDh, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`self.ss.mix_key(&self.re.as_bytes());` : `/* No PSK, so skipping mixKey */`;
		let esInitiatorFill = initiator ?
			`self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));` : `self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));`;
		let seInitiatorFill = initiator ?
			`self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));` : `self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));`;
		let finalFill = isFinal ? [
			`let h: Hash = Hash::from_bytes(from_slice_hashlen(&self.ss.h.as_bytes()));`,
			`let (cs1, cs2) = self.ss.split();`,
			`self.ss.clear();`,
			`Ok((h, cs1, cs2))`
		] : [
			`Ok(())`
		];
		let isBeyondFinal = (message.tokens.length === 0);
		if (isBeyondFinal) {
			return ``;
		}
		let nsLength = alreadyDh ? 'MAC_LENGTH+DHLEN' : 'DHLEN';
		let readFunDeclaration = `\tpub(crate) fn read_message_${suffix}(&mut self, in_out: &mut [u8]) -> ${isFinal? ` Result<(Hash, CipherState, CipherState), NoiseError>` : `Result<(), NoiseError>`} {`;
		let messageTokenParsers = {
			e: [
				`if in_out.len() < MAC_LENGTH+DHLEN {`,
				`\treturn Err(NoiseError::MissingreError);`,
				`}`,
				`let (re, in_out) = in_out.split_at_mut(DHLEN);`,
				`self.re = PublicKey::from_bytes(from_slice_hashlen(re))?;`,
				`self.ss.mix_hash(&self.re.as_bytes()[..DHLEN]);`,
				ePskFill
			].join(`\n\t\t`),
			s: [
				`if in_out.len() < ${nsLength} {`,
				`\treturn Err(NoiseError::MissingrsError);`,
				`}`,
				`let (rs, in_out) = in_out.split_at_mut(${nsLength});`,
				`${alreadyDh ?
					'self.ss.decrypt_and_hash(rs)?;'
				:	'self.ss.mix_hash(rs);'}`,
				`self.rs = PublicKey::from_bytes(from_slice_hashlen(rs))?;`,
			].join(`\n\t\t`),
			ee: [
				`self.ss.mix_key(&self.e.dh(&self.re.as_bytes()));`
			].join(`\n\t\t`),
			es: [
				esInitiatorFill
			].join(`\n\t\t`),
			se: [
				seInitiatorFill
			].join(`\n\t\t`),
			ss: [
				`self.ss.mix_key(&self.s.dh(&self.rs.as_bytes()));`
			].join(`\n\t\t`),
			psk: [
				`self.ss.mix_key_and_hash(&self.psk.as_bytes());`
			].join(`\n\t\t`)
		};
		let readFun = [
			readFunDeclaration
		];
		message.tokens.forEach((token) => {
			readFun.push(messageTokenParsers[token]);
		});
		readFun = readFun.concat([
			`${alreadyDh ?'self.ss.decrypt_and_hash(in_out)?;':'self.ss.mix_hash(in_out);'}`,
			`${finalFill.join('\n\t\t')}`,
		]);
		return `${readFun.join('\n\t\t')}\n\t}`;
	};

	const readMessageFuns = (pattern) => {
		let readFuns = [];
		let finalKex = finalKeyExchangeMessage(pattern);
		for (let i = 0; i < pattern.messages.length; i++) {
			let message = pattern.messages[i];
			let hasPsk = messagesPsk(pattern) >= 0;
			let initiator = (message.dir === 'recv');
			let isFinal = (i === finalKex);
			let alreadyDh = (
				(firstCanEncryptMessage(pattern) >= 0) &&
				(firstCanEncryptMessage(pattern) <= i)
			);
			readFuns.push(
				readMessageFun(message, hasPsk, initiator, alreadyDh, isFinal, util.abc[i])
			);
			if (i > finalKex) {
				break;
			}
		}
		return readFuns;
	};

	const events = (pattern) => {
		return [];
	};

	const queries = (pattern) => {
		return [];
	};

	const globals = (pattern) => {
		return [];
	};

	const initiatorFun = (pattern) => {
		return [];
	};

	const responderFun = (pattern) => {
		return [];
	};

	let repeatingKeysQueryFun = (pattern) => {
		return [];
	};

	const processFuns = (pattern, isOneWayPattern) => {
		let hasPsk = messagesPsk(pattern) >= 0;
		let sendRs = preMessagesSendStatic(pattern);
		let recvRs = preMessagesRecvStatic(pattern);
		let finalKex = finalKeyExchangeMessage(pattern);
		let initSession = [
			`\n\t/// Instantiates a \`NoiseSession\` object. Takes the following as parameters:`,
			`/// - \`initiator\`: \`bool\` variable. To be set as \`true\` when initiating a handshake with a remote party, or \`false\` otherwise.`,
			`/// - \`prologue\`: \`Message\` object. Could optionally contain the name of the protocol to be used.`,
			`/// - \`s\`: \`Keypair\` object. Contains local party's static keypair.`,
			`${sendRs||recvRs?`/// - \`rs\`: \`Option<PublicKey>\`. Contains the remote party's static public key.	Tip: use \`Some(rs_value)\` in case a remote static key exists and \`None\` otherwise.`:''}`,
			`${hasPsk? '/// - \`psk\`: \`Psk\` object. Contains the pre-shared key.' : ''}`,
			`pub fn init_session(initiator: bool, prologue: &[u8], s: Keypair${sendRs||recvRs?', rs: Option<PublicKey>':''}${hasPsk? ', psk: Psk' : ''}) -> NoiseSession {`,
			`\tif initiator {`,
			`\t\tNoiseSession{`,
			`\t\t\ths: HandshakeState::initialize_initiator(prologue, s${recvRs? ', rs.unwrap_or(PublicKey::empty())': ''}, ${hasPsk? 'psk' : 'Psk::default()'}),`,
			`\t\t\tmc: 0,`,
			`\t\t\ti: initiator,`,
			`\t\t\tcs1: CipherState::new(),`,
			`\t\t\tcs2: CipherState::new(),`,
			`\t\t\th: Hash::new(),`,
			`\t\t\tis_transport: false,`,
			`\t\t}`,
			`\t} else {`,
			`\t\tNoiseSession {`,
			`\t\t\ths: HandshakeState::initialize_responder(prologue, s${sendRs? ', rs.unwrap_or(PublicKey::empty())': ''}, ${hasPsk? 'psk' : 'Psk::default()'}),`,
			`\t\t\tmc: 0,`,
			`\t\t\ti: initiator,`,
			`\t\t\tcs1: CipherState::new(),`,
			`\t\t\tcs2: CipherState::new(),`,
			`\t\t\th: Hash::new(),`,
			`\t\t\tis_transport: false,`,
			`\t\t}`,
			`\t}`,
			`}`,
			``
		];
		let sendMessage = [
			`/// Takes a \`&mut [u8]\` containing plaintext as a parameter.`,
			`/// This method returns a \`Ok(()))\` upon successful encryption, and \`Err(NoiseError)\` otherwise`,
			`/// _Note that for security reasons and for better performance, \`send_message\` overwrites the bytes containing the plaintext with the ciphertext. For this reason and to account for the fact that ciphertext and handshake messages encapsulate important values, a pattern specific padding of zero bytes must be added to the following messages.`,
			`/// For transport messages:`,
			`/// All messages must be appended with 16 empty bytes that act as a placeholder for the MAC (Message Authentication Code). These 16 bytes will be overwritten by \`send_message\``,
			`/// For handshake messages:`,
			`/// Kindly use the message lengths listed in the test file under \`../tests/handshake.rs\`, where examples and notes are also provided.`,
			`/// _Also Note that while \`is_transport\` is false the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._`,
			`pub fn send_message(&mut self, in_out: &mut [u8]) -> Result<(), NoiseError> {`,
			`\tif in_out.len() < MAC_LENGTH || in_out.len() > MAX_MESSAGE {`,
			`\t\treturn Err(NoiseError::UnsupportedMessageLengthError);`,
			`\t}`,
		];
		let recvMessage = [
			`/// Takes a \`&mut [u8]\` received from the remote party as a parameter.`,
			`/// This method returns a \`Ok(()))\` upon successful decrytion. and \`Err(NoiseError)\` otherwise.`,
			`/// _Note that for security reasons and for better performance, \`recv_message\` overwrites the bytes containing the ciphertext with the plaintext and clears the MAC from them last 16 bytes of the message, and other keys that might be encapsulated while performing a handshake.`,
			`/// For transport messages:`,
			`/// You should expect to find the plaintext in the same array you passed a reference of as a parameter. The last 16 bytes of this array will be zero bytes and can be safely ignored.`,
			`/// For handshake messages:`,
			`/// Kindly use the message lengths listed in the test file under \`../tests/handshake.rs\`, where examples and notes are also provided.`,
			`///`,
			`/// _Note that while \`is_transport\` is false the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._`,
			`pub fn recv_message(&mut self, in_out: &mut [u8]) -> Result<(), NoiseError> {`,
			`\tif in_out.len() < MAC_LENGTH || in_out.len() > MAX_MESSAGE {`,
			`\t\treturn Err(NoiseError::UnsupportedMessageLengthError);`,
			`\t}`,
		];
		for (let i = 0; i < pattern.messages.length; i++) {
			if (i < finalKex) {
				sendMessage = sendMessage.concat([
					`\t${i > 0? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tself.hs.write_message_${util.abc[i]}(in_out)?;`,
					`\t}`
				]);
				recvMessage = recvMessage.concat([
					`\t${i > 0? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tself.hs.read_message_${util.abc[i]}(in_out)?;`,
					`\t}`
				]);
			} else if (i == finalKex) {
				sendMessage = sendMessage.concat([
					`\t${!isOneWayPattern? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tlet temp = self.hs.write_message_${util.abc[i]}(in_out)?;`,
					`\t\tself.h = temp.0;`,
					`\t\tself.is_transport = true;`,
					`\t\tself.cs1 = temp.1;`,
					`\t\tself.cs2 = ${isOneWayPattern? 'CipherState::new()' : 'temp.2'};`,
					`\t\tself.hs.clear();`,
				]);
				recvMessage = recvMessage.concat([
					`\t${!isOneWayPattern? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tlet temp = self.hs.read_message_${util.abc[i]}(in_out)?;`,
					`\t\t\tself.h = temp.0;`,
					`\t\tself.is_transport = true;`,
					`\t\t\tself.cs1 = temp.1;`,
					`\t\t\tself.cs2 = ${isOneWayPattern? 'CipherState::new()' : 'temp.2'};`,
					`\t\t\tself.hs.clear();`,
				]);
				sendMessage = sendMessage.concat([
					`\t} else if self.i {`,
					`\t\tself.cs1.write_message_regular(in_out)?;`,
					`\t} else {`,
					`\t\tself.${isOneWayPattern? 'cs1' : 'cs2'}.write_message_regular(in_out)?;`,
					`\t}`,
					`\tself.mc += 1;`,
					`\tOk(())`
				]);
				recvMessage = recvMessage.concat([
					`\t} else if self.i {`,
					`\t\tself.${isOneWayPattern? 'cs1' : 'cs2'}.read_message_regular(in_out)?;`,
					`\t} else {`,
					`\t\t\tself.cs1.read_message_regular(in_out)?;`,
					`\t}`,
					`\tself.mc += 1;`,
					`\tOk(())`
				]);
			}
		}
		sendMessage = sendMessage.concat([
			`}`,
			``
		]);
		recvMessage = recvMessage.concat([
			`}`
		]);
		return initSession.concat(sendMessage).concat(recvMessage);
	};

	const parse = (pattern) => {
		let isOneWayPattern = (pattern.messages.length === 1);
		if (isOneWayPattern) {
			pattern.messages.push({
				type: 'Message',
				dir: 'send',
				tokens: []
			});
		}
		let t = JSON.stringify(params);
		let s = typeFuns(pattern).join('\n');
		let i = initializeFuns(pattern).join('\n\n');
		let w = writeMessageFuns(pattern).join('\n\n');
		let r = readMessageFuns(pattern).join('\n\n');
		let e = events(pattern).join('\n');
		let g = globals(pattern).join('\n');
		let a = initiatorFun(pattern).join('\n\t');
		let b = responderFun(pattern).join('\n\t');
		let k = repeatingKeysQueryFun(pattern).join('\n\t');
		let p = processFuns(pattern, isOneWayPattern).join('\n\t');
		let q = queries(pattern).join('\n');
		let parsed = {
			t,
			s,
			i,
			w,
			r,
			e,
			q,
			g,
			a,
			b,
			k,
			p
		};
		return parsed;
	};

	if (typeof(module) !== 'undefined') {
		// Node
		module.exports = {
			parse: parse
		};
	} else {
		// Web
		NOISE2WASM.parse = parse;
	}
})();