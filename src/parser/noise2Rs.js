const NOISE2RS = {
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

	const initializeFun = (pattern, initiator, suffix) => {
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
			`\tpub(crate) fn initialize_${suffix}(prologue: &[u8], s: Keypair, rs: PublicKey, psk: Psk) -> HandshakeState {`,
			`let protocol_name = b"Noise_${pattern.name}_25519_ChaChaPoly_BLAKE2s";`,
			`let mut ss: SymmetricState = SymmetricState::initialize_symmetric(&protocol_name[..]);`,
			`ss.mix_hash(prologue);`
		];
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
			initializeFun(pattern, true, 'initiator'),
			initializeFun(pattern, false, 'responder')
		];
	};

	const writeMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`self.ss.mix_key(&self.e.get_public_key().as_bytes());` : `/* No PSK, so skipping mixKey */`;
		let esInitiatorFill = initiator ?
			`self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));` : `self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));`;
		let seInitiatorFill = initiator ?
			`self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));` : `self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));`;
		let finalFill = isFinal ? [
			`let h: Hash = Hash::new(from_slice_hashlen(self.ss.h.as_bytes()));`,
			`let (cs1, cs2) = self.ss.split();`,
			`self.ss.clear();`,
			`let messagebuffer = MessageBuffer { ne, ns, ciphertext };`,
			`(h, messagebuffer, cs1, cs2)`
		] : [
			`MessageBuffer { ne, ns, ciphertext }`
		];
		let isBeyondFinal = (message.tokens.length === 0);
		if (isBeyondFinal) {
			return ``;
		}
		let writeFunDeclaration = `\tpub(crate) fn write_message_${suffix}(&mut self, payload: &[u8]) -> (${isFinal? `(Hash, MessageBuffer, CipherState, CipherState)` : `MessageBuffer`}) {`;
		let messageTokenParsers = {
			e: [
				`if self.e.is_empty() {`,
				`\tself.e = Keypair::new();`,
				`}`,
				`ne = self.e.get_public_key().as_bytes();`,
				`self.ss.mix_hash(&ne[..]);`,
				ePskFill
			].join(`\n\t\t`),
			s: [
				`if let Some(x) = self.ss.encrypt_and_hash(&self.s.get_public_key().as_bytes()[..]) {`,
				`\tns.clone_from(&x);`,
				`}`
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
			writeFunDeclaration,
			`let ${(message.tokens.indexOf('s') >= 0)? 'mut ': ''}ns: Vec<u8> = Vec::new();`,
			`let ne: [u8; DHLEN]${(message.tokens.indexOf('e') >= 0)? '': ` = ${util.emptyKey}`};`
		];
		message.tokens.forEach((token) => {
			writeFun.push(messageTokenParsers[token]);
		});
		writeFun = writeFun.concat([
			`let mut ciphertext: Vec<u8> = Vec::new();`,
			`if let Some(x) = self.ss.encrypt_and_hash(payload) {`,
			`\tciphertext.clone_from(&x);`,
			`}`
		]);
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
			writeFuns.push(
				writeMessageFun(message, hasPsk, initiator, isFinal, util.abc[i])
			);
			if (i > finalKex) {
				break;
			}
		}
		return writeFuns;
	};

	const readMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`self.ss.mix_key(&self.re.as_bytes());` : `/* No PSK, so skipping mixKey */`;
		let esInitiatorFill = initiator ?
			`self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));` : `self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));`;
		let seInitiatorFill = initiator ?
			`self.ss.mix_key(&self.s.dh(&self.re.as_bytes()));` : `self.ss.mix_key(&self.e.dh(&self.rs.as_bytes()));`;
		let finalFill = isFinal ? [
			`\tlet h: Hash = Hash::new(from_slice_hashlen(self.ss.h.as_bytes()));`,
			`\tlet (cs1, cs2) = self.ss.split();`,
			`\tself.ss.clear();`,
			`\treturn Some((h, plaintext, cs1, cs2));`
		] : [
			`\treturn Some(plaintext);`
		];
		let isBeyondFinal = (message.tokens.length === 0);
		if (isBeyondFinal) {
			return ``;
		}
		let readFunDeclaration = `\tpub(crate) fn read_message_${suffix}(&mut self, message: &mut MessageBuffer) -> (${isFinal? ` Option<(Hash, Vec<u8>, CipherState, CipherState)>` : `Option<Vec<u8>>`}) {`;
		let messageTokenParsers = {
			e: [
				`self.re = PublicKey::from_bytes(message.ne);`,
				`self.ss.mix_hash(&self.re.as_bytes()[..DHLEN]);`,
				ePskFill
			].join(`\n\t\t`),
			s: [
				`if let Some(x) = self.ss.decrypt_and_hash(&message.ns) {`,
				`\tif x.len() != DHLEN {`,
				`\t\treturn None`,
				`\t}`,
				`\tself.rs = PublicKey::from_bytes(from_slice_hashlen(&x[..]));`,
				`} else { return None }`,
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
			readFunDeclaration,
		];
		message.tokens.forEach((token) => {
			readFun.push(messageTokenParsers[token]);
		});
		readFun = readFun.concat([
			`if let Some(plaintext) = self.ss.decrypt_and_hash(&message.ciphertext) {`,
			`${finalFill.join('\n\t\t')}`,
			`}`,
			`None`
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
			readFuns.push(
				readMessageFun(message, hasPsk, initiator, isFinal, util.abc[i])
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
		let finalKex = finalKeyExchangeMessage(pattern);
		let initSession = [
			`\tpub fn init_session(initiator: bool, prologue: Message, s: Keypair, rs: PublicKey${hasPsk? ', psk: Psk' : ''}) -> NoiseSession {`,
			`\tif initiator {`,
			`\t\tNoiseSession{`,
			`\t\t\ths: HandshakeState::initialize_initiator(prologue.as_bytes(), s, rs, ${hasPsk? 'psk' : 'Psk::new()'}),`,
			`\t\t\tmc: 0,`,
			`\t\t\ti: initiator,`,
			`\t\t\tcs1: CipherState::new(),`,
			`\t\t\tcs2: CipherState::new(),`,
			`\t\t\th: Hash::empty(),`,
			`\t\t}`,
			`\t} else {`,
			`\t\tNoiseSession {`,
			`\t\t\ths: HandshakeState::initialize_responder(prologue.as_bytes(), s, rs, ${hasPsk? 'psk' : 'Psk::new()'}),`,
			`\t\t\tmc: 0,`,
			`\t\t\ti: initiator,`,
			`\t\t\tcs1: CipherState::new(),`,
			`\t\t\tcs2: CipherState::new(),`,
			`\t\t\th: Hash::empty(),`,
			`\t\t}`,
			`\t}`,
			`}`
		];
		let sendMessage = [
			`\n\tpub fn send_message(&mut self, message: Message) -> MessageBuffer {`
		];
		let recvMessage = [
			`\n\tpub fn recv_message(&mut self, message: &mut MessageBuffer) -> Option<Vec<u8>> {`,
			`\tlet mut plaintext: Option<Vec<u8>> = None;`
		];
		for (let i = 0; i < pattern.messages.length; i++) {
			if (i < finalKex) {
				sendMessage = sendMessage.concat([
					`\t${i > 0? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tself.mc += 1;`,
					`\t\tself.hs.write_message_${util.abc[i]}(&message.as_bytes()[..])`,
					`\t}`
				]);
				recvMessage = recvMessage.concat([
					`\t${i > 0? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tplaintext = self.hs.read_message_${util.abc[i]}(message);`,
					`\t}`
				]);
			} else if (i == finalKex) {
				sendMessage = sendMessage.concat([
					`\t${!isOneWayPattern? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tlet temp = self.hs.write_message_${util.abc[i]}(&message.as_bytes()[..]);`,
					`\t\tself.h = temp.0;`,
					`\t\tself.cs1 = temp.2;`,
					`\t\tself.cs2 = ${isOneWayPattern? 'CipherState::new()' : 'temp.3'};`,
					`\t\tself.hs.clear();`,
					`\t\tself.mc += 1;`,
					`\t\ttemp.1`,
					`\t}`
				]);
				recvMessage = recvMessage.concat([
					`\t${!isOneWayPattern? 'else ' : ''}if self.mc == ${i} {`,
					`\t\tif let Some(temp) = self.hs.read_message_${util.abc[i]}(message) {`,
					`\t\t\tself.h = temp.0;`,
					`\t\t\tplaintext = Some(temp.1);`,
					`\t\t\tself.cs1 = temp.2;`,
					`\t\t\tself.cs2 = ${isOneWayPattern? 'CipherState::new()' : 'temp.3'};`,
					`\t\t\tself.hs.clear();`,
					`\t\t}`,
					`\t}`
				]);
			} else {
				sendMessage = sendMessage.concat([
					`\telse if self.i {`,
					`\t\tlet buffer = self.cs1.write_message_regular(&message.as_bytes()[..]);`,
					`\t\tself.mc += 1;`,
					`\t\tbuffer`,
					`\t} else {`,
					`\t\tlet buffer = self.${isOneWayPattern? 'cs1' : 'cs2'}.write_message_regular(&message.as_bytes()[..]);`,
					`\t\tself.mc += 1;`,
					`\t\tbuffer`,
					`\t}`,
				]);
				recvMessage = recvMessage.concat([
					`\telse if self.mc > ${finalKex} {`,
					`\t\tif self.i {`,
					`\t\t\tif let Some(msg) = &self.${isOneWayPattern? 'cs1' : 'cs2'}.read_message_regular(message) {`,
					`\t\t\t\tplaintext = Some(msg.to_owned());`,
					`\t\t\t}`,
					`\t\t} else {`,
					`\t\t\tif let Some(msg) = &self.cs1.read_message_regular(message) {`,
					`\t\t\t\tplaintext = Some(msg.to_owned());`,
					`\t\t\t}`,
					`\t\t}`,
					`\t}`,
					`\tself.mc += 1;`,
					`\tplaintext`
				]);
				break;
			}
		}
		sendMessage = sendMessage.concat([
			`}`
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
		NOISE2RS.parse = parse;
	}

})();