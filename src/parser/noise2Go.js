const NOISE2GO = {
	parse: () => {}
};

(() => {

	const params = {
		attacker: 'passive'
	};

	const util = {
		emptyKey: 'emptyKey',
		emptyKeyPair: 'keypair{emptyKey, emptyKey}',
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
				e: `mixHash(&ss, e.public_key[:])`,
				s: `mixHash(&ss, s.public_key[:])`,
				'e, s': `mixHash(mixHash(&ss, e.public_key[:]), s.public_key[:])`
			},
			recv: {
				e: `mixHash(&ss, re[:])`,
				s: `mixHash(&ss, rs[:])`,
				'e, s': `mixHash(&mixHash(ss, re[:]), rs[:])`
			}
		};
		let initFun = [
			`func initialize${suffix}(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {`,
			`var ss symmetricstate`,
			`var e keypair`,
			`var re [32]byte`,
			`name := []byte("Noise_${pattern.name}_25519_ChaChaPoly_BLAKE2s")`,
			`ss = initializeSymmetric(name)`,
			`mixHash(&ss, prologue)`
		];
		pattern.preMessages.forEach((preMessage) => {
			let dir = preMessage.dir;
			if (!initiator) {
				dir = (dir === 'send') ? 'recv' : 'send';
			}
			initFun.push(preMessageTokenParsers[dir][preMessage.tokens]);
		});
		initFun.push(`return handshakestate{ss, s, e, rs, re, psk}`);
		return `${initFun.join('\n\t')}\n}`;
	};

	const initializeFuns = (pattern) => {
		return [
			initializeFun(pattern, true, 'Initiator'),
			initializeFun(pattern, false, 'Responder')
		];
	};

	const writeMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`mixKey(&hs.ss, hs.e.public_key)` : `/* No PSK, so skipping mixKey */`;
		let esInitiatorFill = initiator ?
			`mixKey(&hs.ss, dh(hs.e.private_key, hs.rs))` : `mixKey(&hs.ss, dh(hs.s.private_key, hs.re))`;
		let seInitiatorFill = initiator ?
			`mixKey(&hs.ss, dh(hs.s.private_key, hs.re))` : `mixKey(&hs.ss, dh(hs.e.private_key, hs.rs))`;
		let finalFill = isFinal ? [
			`cs1, cs2 := split(&hs.ss)`,
			`return hs.ss.h, messageBuffer, cs1, cs2`
		] : [
			`return hs, messageBuffer`
		];
		let isBeyondFinal = (message.tokens.length === 0);
		let writeFunDeclaration = isBeyondFinal ?
			`func writeMessageRegular(cs *cipherstate, payload []byte) (*cipherstate, messagebuffer) {` :
			`func writeMessage${suffix}(hs *handshakestate, payload []byte) (${isFinal? `[32]byte, messagebuffer, cipherstate, cipherstate` : `*handshakestate, messagebuffer`}) {`;
		let messageTokenParsers = {
			e: [
				`hs.e = generateKeypair()`,
				`ne = hs.e.public_key`,
				`mixHash(&hs.ss, ne[:])`,
				ePskFill
			].join(`\n\t`),
			s: [
				`spk := make([]byte, len(hs.s.public_key))`,
				`copy(spk[:], hs.s.public_key[:])`,
				`_, ns = encryptAndHash(&hs.ss, spk)`,
			].join(`\n\t`),
			ee: [
				`mixKey(&hs.ss, dh(hs.e.private_key, hs.re))`
			].join(`\n\t`),
			es: [
				esInitiatorFill
			].join(`\n\t`),
			se: [
				seInitiatorFill
			].join(`\n\t`),
			ss: [
				`mixKey(&hs.ss, dh(hs.s.private_key, hs.rs))`
			].join(`\n\t`),
			psk: [
				`mixKeyAndHash(&hs.ss, hs.psk)`
			].join(`\n\t`),
		};
		let writeFun = [
			writeFunDeclaration,
			`ne, ns, ciphertext := emptyKey, []byte{}, []byte{}`
		];
		message.tokens.forEach((token) => {
			writeFun.push(messageTokenParsers[token]);
		});
		writeFun = writeFun.concat(isBeyondFinal ? [
			`cs, ciphertext = encryptWithAd(cs, []byte{}, payload)`,
			`messageBuffer := messagebuffer{ne, ns, ciphertext}`
		] : [
			`_, ciphertext = encryptAndHash(&hs.ss, payload)`,
			`messageBuffer := messagebuffer{ne, ns, ciphertext}`,
		]);
		writeFun = writeFun.concat(isBeyondFinal ? `return cs, messageBuffer` : finalFill);
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
		let ePskFill = hasPsk ?
			`mixKey(&hs.ss, hs.re)` : `/* No PSK, so skipping mixKey */`;
		let esInitiatorFill = initiator ?
			`mixKey(&hs.ss, dh(hs.e.private_key, hs.rs))` : `mixKey(&hs.ss, dh(hs.s.private_key, hs.re))`;
		let seInitiatorFill = initiator ?
			`mixKey(&hs.ss, dh(hs.s.private_key, hs.re))` : `mixKey(&hs.ss, dh(hs.e.private_key, hs.rs))`;
		let finalFill = isFinal ? [
			`cs1, cs2 := split(&hs.ss)`,
			`return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2`
		] : [
			`return hs, plaintext, (valid1 && valid2)`
		];
		let isBeyondFinal = (message.tokens.length === 0);
		let readFunDeclaration = isBeyondFinal ?
			`func readMessageRegular(cs *cipherstate, message *messagebuffer) (*cipherstate, []byte, bool) {` :
			`func readMessage${suffix}(hs *handshakestate, message *messagebuffer) (${isFinal? `[32]byte, []byte, bool, cipherstate, cipherstate` : `*handshakestate, []byte, bool`}) {`;
		let messageTokenParsers = {
			e: [
				`if validatePublicKey(message.ne[:]) {`,
				`\ths.re = message.ne`,
				`}`,
				`mixHash(&hs.ss, hs.re[:])`,
				ePskFill
			].join(`\n\t`),
			s: [
				`_, ns, valid1 := decryptAndHash(&hs.ss, message.ns)`,
				`if valid1 && len(ns) == 32 && validatePublicKey(message.ns[:]) {`,
				`\tcopy(hs.rs[:], ns)`,
				`}`,
			].join(`\n\t`),
			ee: [
				`mixKey(&hs.ss, dh(hs.e.private_key, hs.re))`
			].join(`\n\t`),
			es: [
				esInitiatorFill
			].join(`\n\t`),
			se: [
				seInitiatorFill
			].join(`\n\t`),
			ss: [
				`mixKey(&hs.ss, dh(hs.s.private_key, hs.rs))`
			].join(`\n\t`),
			psk: [
				`mixKeyAndHash(&hs.ss, hs.psk)`
			].join(`\n\t`)
		};
		let readFun = [
			readFunDeclaration,
			isBeyondFinal ? `/* No encrypted keys */` : `valid1 := true`
		];
		message.tokens.forEach((token) => {
			readFun.push(messageTokenParsers[token]);
		});
		readFun = readFun.concat(isBeyondFinal ? [
			`_, plaintext, valid2 := decryptWithAd(cs, []byte{}, message.ciphertext)`,
			`return cs, plaintext, valid2`
		] : [
			`_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)`,
			`${finalFill.join('\n\t')}`
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
			`func InitSession(initiator bool, prologue []byte, s keypair, rs [32]byte${hasPsk? ', psk [32]byte' : ''}) noisesession {`,
			`\tvar session noisesession`,
			`\t${hasPsk? '/* PSK defined by user */' : 'psk := emptyKey'}`,
			`\tif initiator {`,
			`\t\tsession.hs = initializeInitiator(prologue, s, rs, psk)`,
			`\t} else {`,
			`\t\tsession.hs = initializeResponder(prologue, s, rs, psk)`,
			`\t}`,
			`\tsession.i = initiator`,
			`\tsession.mc = 0`,
			`\treturn session`,
			`}`
		];
		let sendMessage = [
			`\nfunc SendMessage(session *noisesession, message []byte) (*noisesession, messagebuffer) {`,
			`\tvar messageBuffer messagebuffer`
		];
		let recvMessage = [
			`\nfunc RecvMessage(session *noisesession, message *messagebuffer) (*noisesession, []byte, bool) {`,
			`\tvar plaintext []byte`,
			`\tvar valid bool`
		];
		for (let i = 0; i < pattern.messages.length; i++) {
			if (i < finalKex) {
				sendMessage = sendMessage.concat([
					`\tif session.mc == ${i} {`,
					`\t\t_, messageBuffer = writeMessage${util.abc[i]}(&session.hs, message)`,
					`\t}`
				]);
				recvMessage = recvMessage.concat([
					`\tif session.mc == ${i} {`,
					`\t\t_, plaintext, valid = readMessage${util.abc[i]}(&session.hs, message)`,
					`\t}`
				]);
			} else if (i == finalKex) {
				sendMessage = sendMessage.concat([
					`\tif session.mc == ${i} {`,
					`\t\tsession.h, messageBuffer, session.cs1, ${isOneWayPattern? `_` : `session.cs2`} = writeMessage${util.abc[i]}(&session.hs, message)`,
					`\t\tsession.hs = handshakestate{}`,
					`\t}`
				]);
				recvMessage = recvMessage.concat([
					`\tif session.mc == ${i} {`,
					`\t\tsession.h, plaintext, valid, session.cs1, ${isOneWayPattern? `_` : `session.cs2`} = readMessage${util.abc[i]}(&session.hs, message)`,
					`\t\tsession.hs = handshakestate{}`,
					`\t}`
				]);
				sendMessage = sendMessage.concat([
					`\tif session.mc > ${finalKex} {`,
					`\t\tif session.i {`,
					`\t\t\t_, messageBuffer = writeMessageRegular(&session.cs1, message)`,
					`\t\t} else {`,
					`\t\t\t_, messageBuffer = writeMessageRegular(&session.${isOneWayPattern? `cs1` : `cs2`}, message)`,
					`\t\t}`,
					`\t}`
				]);
				recvMessage = recvMessage.concat([
					`\tif session.mc > ${finalKex} {`,
					`\t\tif session.i {`,
					`\t\t\t_, plaintext, valid = readMessageRegular(&session.${isOneWayPattern? `cs1` : `cs2`}, message)`,
					`\t\t} else {`,
					`\t\t\t_, plaintext, valid = readMessageRegular(&session.cs1, message)`,
					`\t\t}`,
					`\t}`
				]);
			}
		}
		sendMessage = sendMessage.concat([
			`\tsession.mc = session.mc + 1`,
			`\treturn session, messageBuffer`,
			`}`
		]);
		recvMessage = recvMessage.concat([
			`\tsession.mc = session.mc + 1`,
			`\treturn session, plaintext, valid`,
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
		let p = processFuns(pattern, isOneWayPattern).join('\n');
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
		NOISE2GO.parse = parse;
	}

})();