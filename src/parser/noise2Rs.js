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
	abc: ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'],
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
			e: `ss.MixHash(&e.pk.0[..]);`,
			s: `ss.MixHash(&s.pk.0[..]);`,
			'e, s': `ss.MixHash(&e.pk.0[..]); ss.MixHash(&s.pk.0[..]);`
		},
		recv: {
			e: `ss.MixHash(&re[..]);`,
			s: `ss.MixHash(&rs[..]);`,
			'e, s': `ss.MixHash(&re[:]); ss.MixHash(&rs[:]);`
		}
	};
	let initFun = [
		`fn Initialize${suffix}(prologue: &[u8], s: Keypair, rs: [u8; DHLEN], psk: [u8; PSK_LENGTH]) -> HandshakeState {`,
		`let protocol_name = b"Noise_${pattern.name}_25519_ChaChaPoly_BLAKE2s";`,
		`let mut ss: SymmetricState = SymmetricState::InitializeSymmetric(&protocol_name[..]);`,
		`ss.MixHash(prologue);`
	];
	pattern.preMessages.forEach((preMessage) => {
		let dir = preMessage.dir;
		if (!initiator) {
			dir = (dir === 'send')? 'recv' : 'send';
		}
		initFun.push(preMessageTokenParsers[dir][preMessage.tokens]);
	});
	initFun.push(`HandshakeState{ss, s, e: ${util.emptyKeyPair}, rs, re: ${util.emptyKey}, psk}`);
	return `${initFun.join('\n\t')}\n}`;
};

const initializeFuns = (pattern) => {
	return [
		initializeFun(pattern, true, 'Initiator'),
		initializeFun(pattern, false, 'Responder')
	];
};

const writeMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
	let ePskFill = hasPsk?
		`self.ss.MixKey(&self.e.pk.0);` : `/* No PSK, so skipping mixKey */`;
	let esInitiatorFill = initiator?
		`self.ss.MixKey(&DH(&self.e, &self.rs));` : `self.ss.MixKey(&DH(&self.s, &self.re));`;
	let seInitiatorFill = initiator?
		`self.ss.MixKey(&DH(&self.s, &self.re));` : `self.ss.MixKey(&DH(&self.e, &self.rs));`;
	let finalFill = isFinal? [
		`let (cs1, cs2) = self.ss.Split();`,
		`let messagebuffer: MessageBuffer = MessageBuffer { ne, ns, ciphertext };`,
		`(self.ss.h, messagebuffer, cs1, cs2)`
	] : [
		`MessageBuffer { ne, ns, ciphertext }`
	];
	let isBeyondFinal = (message.tokens.length === 0);
	if (isBeyondFinal) {
		return ``;
	}
	let writeFunDeclaration = `fn WriteMessage${suffix}(&mut self, payload: &[u8]) -> (${isFinal? `([u8; 32], MessageBuffer, CipherState, CipherState)` : `MessageBuffer`}) {`;
	let messageTokenParsers = {
		e: [
			`self.e = GENERATE_KEYPAIR();`,
			`let ne = self.e.pk.0;`,
			`let ns: Vec<u8> = Vec::from(&zerolen[..]);`,
			`self.ss.MixHash(&ne[..]);`,
			ePskFill
		].join(`\n\t`),
		s: [
			`let mut ns: Vec<u8> = Vec::new();`,
			`if let Some(x) = self.ss.EncryptAndHash(&self.s.pk.0[..]) {`,
			`\tns.clone_from(&x);`,
			`}`
		].join(`\n\t`),
		ee: [
			`self.ss.MixKey(&DH(&self.e, &self.re));`
		].join(`\n\t`),
		es: [
			esInitiatorFill
		].join(`\n\t`),
		se: [
			seInitiatorFill
		].join(`\n\t`),
		ss: [
			`self.ss.MixKey(&DH(&self.s, &self.rs));`
		].join(`\n\t`),
		psk: [
			`self.ss.MixKeyAndHash(&self.psk);`
		].join(`\n\t`),
	};
	let writeFun = [
		writeFunDeclaration
	];
	message.tokens.forEach((token) => {
		writeFun.push(messageTokenParsers[token]);
	});
	writeFun = writeFun.concat([
		`let mut ciphertext: Vec<u8> = Vec::new();`,
		`if let Some(x) = self.ss.EncryptAndHash(payload) {`,
		`\tciphertext.clone_from(&x);`,
		`}`
	]);
	writeFun = writeFun.concat(finalFill);
	return `${writeFun.join('\n\t')}\n}`;
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
	let ePskFill = hasPsk?
		`self.ss.MixKey(&self.re);` : `/* No PSK, so skipping mixKey */`;
	let esInitiatorFill = initiator?
		`self.ss.MixKey(&DH(&self.e, &self.rs));` : `self.ss.MixKey(&DH(&self.s, &self.re));`;
	let seInitiatorFill = initiator?
		`self.ss.MixKey(&DH(&self.s, &self.re));` : `self.ss.MixKey(&DH(&self.e, &self.rs));`;
	let finalFill = isFinal? [
		`\tlet (cs1, cs2) = self.ss.Split();`,
		`\treturn Some((self.ss.h, plaintext, cs1, cs2));`
	] : [
		`\treturn Some(plaintext);`
	];
	let isBeyondFinal = (message.tokens.length === 0);
	if (isBeyondFinal) {
		return ``;
	}
	let readFunDeclaration = `fn ReadMessage${suffix}(&mut self, message: &mut MessageBuffer) -> (${isFinal? `Option<([u8; 32], Vec<u8>, CipherState, CipherState)>` : `Option<Vec<u8>>`}) {`;
	let messageTokenParsers = {
		e: [
			`self.re.copy_from_slice(&message.ne[..]);`,
			`self.ss.MixHash(&self.re[..DHLEN]);`,
			ePskFill
		].join(`\n\t`),
		s: [
			`if let Some(x) = self.ss.DecryptAndHash(&message.ns) {`,
			`\tif x.len() != DHLEN {`,
			`\t\treturn None`,
			`\t}`,
			`\tself.rs.copy_from_slice(&x);`,
			`} else { return None }`,
		].join(`\n\t`),
		ee: [
			`self.ss.MixKey(&DH(&self.e, &self.re));`
		].join(`\n\t`),
		es: [
			esInitiatorFill
		].join(`\n\t`),
		se: [
			seInitiatorFill
		].join(`\n\t`),
		ss: [
			`self.ss.MixKey(&DH(&self.s, &self.rs));`
		].join(`\n\t`),
		psk: [
			`self.ss.MixKeyAndHash(&self.psk);`
		].join(`\n\t`)
	};
	let readFun = [
		readFunDeclaration,
	];
	message.tokens.forEach((token) => {
		readFun.push(messageTokenParsers[token]);
	});
	readFun = readFun.concat([
		`if let Some(plaintext) = self.ss.DecryptAndHash(&message.ciphertext) {`,
		`${finalFill.join('\n\t')}`,
		`}`,
		`None`
	]);
	return `${readFun.join('\n\t')}\n}`;
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
		`\tpub fn InitSession(initiator: bool, prologue: &[u8], s: Keypair, rs: [u8; DHLEN]${hasPsk? ', psk: [u8; PSK_LENGTH]' : ''}) -> NoiseSession {`,
		`\tif initiator {`,
		`\t\tNoiseSession{`,
		`\t\t\ths: HandshakeState::InitializeInitiator(prologue, s, rs, ${hasPsk? 'psk' : util.emptyKey}),`,
		`\t\t\tmc: 0,`,
		`\t\t\ti: initiator,`,
		`\t\t\tcs1: CipherState::InitializeKey(&EMPTY_KEY),`,
		`\t\t\tcs2: CipherState::InitializeKey(&EMPTY_KEY),`,
		`\t\t\th: [0u8; 32],`,
		`\t\t}`,
		`\t} else {`,
		`\t\tNoiseSession {`,
		`\t\t\ths: HandshakeState::InitializeResponder(prologue, s, rs, ${hasPsk? 'psk' : util.emptyKey}),`,
		`\t\t\tmc: 0,`,
		`\t\t\ti: initiator,`,
		`\t\t\tcs1: CipherState::InitializeKey(&EMPTY_KEY),`,
		`\t\t\tcs2: CipherState::InitializeKey(&EMPTY_KEY),`,
		`\t\t\th: [0u8; 32],`,
		`\t\t}`,
		`\t}`,
		`}`
	];
	let sendMessage = [
		`\n\tpub fn SendMessage(&mut self, message: &[u8]) -> MessageBuffer {`,
		`\tif self.cs1.n < MAX_NONCE && self.cs2.n < MAX_NONCE`,
		`\t&& self.hs.ss.cs.n < MAX_NONCE && message.len() < 65535 {`,
		`\t\tlet mut buffer: MessageBuffer = MessageBuffer {`,
		`\t\t\tne: EMPTY_KEY,`,
		`\t\t\tns: Vec::from(&zerolen[..]),`,
		`\t\t\tciphertext: Vec::from(&zerolen[..]),`,
		`\t\t};`
	];
	let recvMessage = [
		`\n\tpub fn RecvMessage(&mut self, message: &mut MessageBuffer) -> Option<Vec<u8>> {`,
		`\tif self.cs1.n < MAX_NONCE && self.cs2.n < MAX_NONCE`,
		`\t&& self.hs.ss.cs.n < MAX_NONCE && message.ciphertext.len() < 65535 {`,
		`\t\tlet mut plaintext: Option<Vec<u8>> = None;`
	];
	for (let i = 0; i < pattern.messages.length; i++) {
		if (i < finalKex) {
			sendMessage = sendMessage.concat([
				`\t\tif self.mc == ${i} {`,
				`\t\t\tbuffer = self.hs.WriteMessage${util.abc[i]}(message);`,
				`\t\t}`
			]);
			recvMessage = recvMessage.concat([
				`\t\tif self.mc == ${i} {`,
				`\t\t\tplaintext = self.hs.ReadMessage${util.abc[i]}(message);`,
				`\t\t}`
			]);
		} else if (i == finalKex) {
			sendMessage = sendMessage.concat([
				`\t\tif self.mc == ${i} {`,
				`\t\t\tlet temp = self.hs.WriteMessage${util.abc[i]}(message);`,
				`\t\t\tself.h = temp.0;`,
				`\t\t\tbuffer = temp.1;`,
				`\t\t\tself.cs1 = temp.2;`,
				`\t\t\tself.cs2 = temp.3;`,
				`\t\t\t// Drop hs here`,
				`\t\t\tself.hs = HandshakeState {`,
				`\t\t\t\tss: SymmetricState::InitializeSymmetric(b""),`,
				`\t\t\t\ts: ${util.emptyKeyPair},`,
				`\t\t\t\te: ${util.emptyKeyPair},`,
				`\t\t\t\trs: ${util.emptyKey},`,
				`\t\t\t\tre: ${util.emptyKey},`,
				`\t\t\t\tpsk: ${util.emptyKey},`,
				`\t\t\t};`,
				`\t\t}`
			]);
			recvMessage = recvMessage.concat([
				`\t\tif self.mc == ${i} {`,
				`\t\t\tif let Some(temp) = self.hs.ReadMessageB(message) {`,
				`\t\t\t\tself.h = temp.0;`,
				`\t\t\t\tplaintext = Some(temp.1);`,
				`\t\t\t\tself.cs1 = temp.2;`,
				`\t\t\t\tself.cs2 = temp.3;`,
				`\t\t\t\t// Drop hs here`,
				`\t\t\t\tself.hs = HandshakeState {`,
				`\t\t\t\t\tss: SymmetricState::InitializeSymmetric(b""),`,
				`\t\t\t\t\ts: ${util.emptyKeyPair},`,
				`\t\t\t\t\te: ${util.emptyKeyPair},`,
				`\t\t\t\t\trs: ${util.emptyKey},`,
				`\t\t\t\t\tre: ${util.emptyKey},`,
				`\t\t\t\t\tpsk: ${util.emptyKey},`,
				`\t\t\t\t};`,
				`\t\t\t}`,
				`\t\t}`
			]);
		} else {
			sendMessage = sendMessage.concat([
				`\t\tif self.mc > ${finalKex} {`,
				`\t\t\tif self.i {`,
				`\t\t\t\tbuffer = self.cs1.WriteMessageRegular(message);`,
				`\t\t\t} else {`,
				`\t\t\t\tbuffer = self.cs2.WriteMessageRegular(message);`,
				`\t\t\t}`,
				`\t\t}`
			]);
			recvMessage = recvMessage.concat([
				`\t\tif self.mc > ${finalKex} {`,
				`\t\t\tif self.i {`,
				`\t\t\t\tif let Some(msg) = self.cs2.ReadMessageRegular(message) {`,
				`\t\t\t\t\tplaintext = Some(msg);`,
				`\t\t\t\t}`,
				`\t\t\t} else {`,
				`\t\t\t\tif let Some(msg) = self.cs1.ReadMessageRegular(message) {`,
				`\t\t\t\t\tplaintext = Some(msg);`,
				`\t\t\t\t}`,
				`\t\t\t}`,
				`\t\t}`
			]);
			break;
		}
	}
	sendMessage = sendMessage.concat([
		`\t\tself.mc += 1;`,
		`\t\tbuffer`,
		`\t} else {`,
		`\t\tif message.len() > 65535 {`,
		`\t\t\tpanic!("Message too big.");`,
		`\t\t}`,
		`\t\tpanic!("Maximum number of messages reached.");`,
		`\t}`,
		`}`
	]);
	recvMessage = recvMessage.concat([
		`\t\tself.mc += 1;`,
		`\t\tplaintext`,
		`\t} else {`,
		`\t\tif message.ciphertext.len() > 65535 {`,
		`\t\t\tpanic!("Message too big.");`,
		`\t\t}`,
		`\t\tpanic!("Maximum number of messages reached.");`,
		`\t}`,
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
	let parsed = {t, s, i, w, r, e, q, g, a, b, k, p};
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