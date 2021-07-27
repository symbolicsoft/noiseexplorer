const NOISE2PV = {
	parse: () => {}
};

(() => {

	const params = {
		attacker: 'active'
	};

	const util = {
		emptyKey: 'bit2key(empty)',
		emptyKeyPair: 'keypairpack(bit2key(empty), bit2key(empty))',
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
		for (let i = 0; i < pattern.messages.length; i++) {
			if (pattern.messages[i].tokens.indexOf('psk') >= 0) {
				r = i;
				break;
			}
		}
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
		let stage = [];
		let state = [];
		let msg = [];
		pattern.messages.forEach((message, i) => {
			let abc = util.abc[i];
			stage.push(`fun stagepack_${abc}(sessionid):stage [data].`);
			if (message.tokens.length) {
				state.push(`fun statepack_${abc}(handshakestate):state [data].`);
			} else {
				state.push(`fun statepack_${abc}(handshakestate, cipherstate, cipherstate):state [data].`);
			}
			msg.push(`fun msg_${abc}(principal, principal, sessionid):bitstring [private].`);
		});
		stage.push('');
		state.push('');
		return stage.concat(state.concat(msg.concat()));
	};

	const initializeFun = (pattern, initiator, suffix) => {
		let preMessageTokenParsers = {
			send: {
				e: `let ss = mixHash(ss, key2bit(getpublickey(e))) in`,
				s: `let ss = mixHash(ss, key2bit(getpublickey(s))) in`,
				'e, s': `let ss = mixHash(mixHash(ss, getpublickey(e)), getpublickey(s)) in`
			},
			recv: {
				e: `let ss = mixHash(ss, key2bit(re)) in`,
				s: `let ss = mixHash(ss, key2bit(rs)) in`,
				'e, s': `let ss = mixHash(mixHash(ss, key2bit(re)), key2bit(rs)) in`
			}
		};
		let initFun = [
			`letfun initialize_${suffix}(prologue:bitstring, s:keypair, e:keypair, rs:key, re:key, psk:key) =`,
			`let ss = mixHash(initializeSymmetric(somename), prologue) in`
		];
		pattern.preMessages.forEach((preMessage) => {
			let dir = preMessage.dir;
			if (!initiator) {
				dir = (dir === 'send') ? 'recv' : 'send';
			}
			initFun.push(preMessageTokenParsers[dir][preMessage.tokens]);
		});
		initFun.push(`handshakestatepack(ss, s, e, rs, re, psk, ${initiator}).`);
		return initFun.join('\n\t');
	};

	const initializeFuns = (pattern) => {
		return [
			initializeFun(pattern, true, 'initiator'),
			initializeFun(pattern, false, 'responder')
		];
	};

	const writeMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`let ss = mixKey(ss, getpublickey(e)) in` : `(* No PSK, so skipping mixKey *)`;
		let esInitiatorFill = initiator ?
			`let ss = mixKey(ss, dh(e, rs)) in` : `let ss = mixKey(ss, dh(s, re)) in`;
		let seInitiatorFill = initiator ?
			`let ss = mixKey(ss, dh(s, re)) in` : `let ss = mixKey(ss, dh(e, rs)) in`;
		let finalFill = isFinal ? [
			`let (ssi:symmetricstate, cs1:cipherstate, cs2:cipherstate) = split(ss) in`,
			`(hs, message_buffer, cs1, cs2).`
		] : [
			`(hs, message_buffer).`
		];
		let messageTokenParsers = {
			e: [
				`let e = generate_keypair(key_e(me, them, sid)) in`,
				`let ne = key2bit(getpublickey(e)) in`,
				`let ss = mixHash(ss, ne) in`,
				ePskFill
			].join(`\n\t`),
			s: [
				`let s = generate_keypair(key_s(me)) in`,
				`let (ss:symmetricstate, ns:bitstring) = encryptAndHash(ss, key2bit(getpublickey(s))) in`
			].join(`\n\t`),
			ee: [
				`let ss = mixKey(ss, dh(e, re)) in`
			].join(`\n\t`),
			es: [
				esInitiatorFill
			].join(`\n\t`),
			se: [
				seInitiatorFill
			].join(`\n\t`),
			ss: [
				`let ss = mixKey(ss, dh(s, rs)) in`
			].join(`\n\t`),
			psk: [
				`let ss = mixKeyAndHash(ss, psk) in`
			].join(`\n\t`)
		};
		let writeFun = [
			`letfun writeMessage_${suffix}(me:principal, them:principal, hs:handshakestate, payload:bitstring, sid:sessionid) =`,
			`let (ss:symmetricstate, s:keypair, e:keypair, rs:key, re:key, psk:key, initiator:bool) = handshakestateunpack(hs) in`,
			`let (ne:bitstring, ns:bitstring, ciphertext:bitstring) = (empty, empty, empty) in`
		];
		message.tokens.forEach((token) => {
			writeFun.push(messageTokenParsers[token]);
		});
		writeFun = writeFun.concat([
			`let (ss:symmetricstate, ciphertext:bitstring) = encryptAndHash(ss, payload) in`,
			`let hs = handshakestatepack(ss, s, e, rs, re, psk, initiator) in`,
			`let message_buffer = concat3(ne, ns, ciphertext) in`,
		]);
		writeFun = writeFun.concat(finalFill);
		return writeFun.join('\n\t');
	};

	const writeMessageFuns = (pattern) => {
		let writeFuns = [];
		let finalKex = finalKeyExchangeMessage(pattern);
		pattern.messages.forEach((message, i) => {
			let hasPsk = messagesPsk(pattern) >= 0;
			let initiator = (message.dir === 'send');
			let isFinal = (i === finalKex);
			writeFuns.push(
				writeMessageFun(message, hasPsk, initiator, isFinal, util.abc[i])
			);
		});
		return writeFuns;
	};

	const readMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
		let ePskFill = hasPsk ?
			`let ss = mixKey(ss, re) in` : `(* No PSK, so skipping mixKey *)`;
		let esInitiatorFill = initiator ?
			`let ss = mixKey(ss, dh(e, rs)) in` : `let ss = mixKey(ss, dh(s, re)) in`;
		let seInitiatorFill = initiator ?
			`let ss = mixKey(ss, dh(s, re)) in` : `let ss = mixKey(ss, dh(e, rs)) in`;
		let authStaticKey = (message.tokens.indexOf('s') >= 0) ?
			` && (rs = getpublickey(generate_keypair(key_s(them))))` : ``;
		let finalFill = isFinal ? [
			`\tlet (ssi:symmetricstate, cs1:cipherstate, cs2:cipherstate) = split(ss) in`,
			`\t(hs, plaintext, true, cs1, cs2)`
		] : [
			`\t(hs, plaintext, true)`
		];
		let messageTokenParsers = {
			e: [
				`let re = bit2key(ne) in`,
				`let ss = mixHash(ss, key2bit(re)) in`,
				ePskFill
			].join(`\n\t`),
			s: [
				`let (ss:symmetricstate, ne:bitstring, valid1:bool) = decryptAndHash(ss, ns) in`,
				`let rs = bit2key(ne) in`
			].join(`\n\t`),
			ee: [
				`let ss = mixKey(ss, dh(e, re)) in`
			].join(`\n\t`),
			es: [
				esInitiatorFill
			].join(`\n\t`),
			se: [
				seInitiatorFill
			].join(`\n\t`),
			ss: [
				`let ss = mixKey(ss, dh(s, rs)) in`
			].join(`\n\t`),
			psk: [
				`let ss = mixKeyAndHash(ss, psk) in`
			].join(`\n\t`)
		};
		let readFun = [
			`letfun readMessage_${suffix}(me:principal, them:principal, hs:handshakestate, message:bitstring, sid:sessionid) =`,
			`let (ss:symmetricstate, s:keypair, e:keypair, rs:key, re:key, psk:key, initiator:bool) = handshakestateunpack(hs) in`,
			`let (ne:bitstring, ns:bitstring, ciphertext:bitstring) = deconcat3(message) in`,
			`let valid1 = true in`
		];
		message.tokens.forEach((token) => {
			readFun.push(messageTokenParsers[token]);
		});
		readFun = readFun.concat([
			`let (ss:symmetricstate, plaintext:bitstring, valid2:bool) = decryptAndHash(ss, ciphertext) in`,
			`if ((valid1 && valid2)${authStaticKey}) then (`,
			`\tlet hs = handshakestatepack(ss, s, e, rs, re, psk, initiator) in`,
			`${finalFill.join('\n\t')}`,
			`).`
		]);
		return readFun.join('\n\t');
	};

	const readMessageFuns = (pattern) => {
		let readFuns = [];
		let finalKex = finalKeyExchangeMessage(pattern);
		pattern.messages.forEach((message, i) => {
			let hasPsk = messagesPsk(pattern) >= 0;
			let initiator = (message.dir === 'recv');
			let isFinal = (i === finalKex);
			readFuns.push(
				readMessageFun(message, hasPsk, initiator, isFinal, util.abc[i])
			);
		});
		return readFuns;
	};

	const events = (pattern) => {
		let ev = [
			'event Error().',
			'event SendEnd(bool).',
			'event RecvEnd(bool).',
			'event SendMsg(principal, principal, stage, bitstring).',
			'event RecvMsg(principal, principal, stage, bitstring).',
			'event LeakS(phasen, principal).',
			'event LeakPsk(phasen, principal, principal).'
		];
		pattern.messages.forEach((message, i) => {
			ev.push(`event RepeatingKey_${util.abc[i]}(principal).`);
		});
		return ev;
	};

	const queries = (pattern) => {
		let quer = [
			`query c:principal, m:bitstring, sid_a:sessionid, sid_b:sessionid, s:stage, b:bitstring, px:phasen, py:phasen, pz:phasen;`,
		];
		let sends = preMessagesSendStatic(pattern) ? 0 : messagesSendStatic(pattern);
		let recvs = preMessagesRecvStatic(pattern) ? 0 : messagesRecvStatic(pattern);
		let psk = messagesPsk(pattern);
		pattern.messages.forEach((message, i) => {
			let send = (i % 2) ? 'bob' : 'alice';
			let recv = (i % 2) ? 'alice' : 'bob';
			let sendsid = `sid_${send[0]}`;
			let recvsid = `sid_${recv[0]}`;
			let abc = util.abc[i];
			let confQuery21 = (params.attacker === 'active') ? '2' : '1';
			let confQuery43 = (params.attacker === 'active') ? '4' : '3';
			let leakS = (px, py, isSend, includePsk, force) => {
				let x = isSend ? send : recv;
				let y = (x === 'alice') ? sends : recvs;
				let s = ((y >= 0) || force) ? `(event(LeakS(${px}, ${x})))` : '';
				let p = (includePsk && (psk >= 0) && (psk <= i)) ? `(event(LeakPsk(${py}, alice, bob)))` : '';
				let a = (s.length && p.length) ? ` && ` : '';
				return `${s}${a}${p}`;
			};
			let conf21 = () => {
				return leakS('px', 'py', false, true, false) || 'false';
			};
			let conf43 = () => {
				let s = leakS('phase0', 'phase0', false, true, true);
				let p = leakS('px', 'py', false, true, true);
				let b = leakS('pz', 'pz', true, false, true);
				let a = (s.length && p.length) ? ` || ` : '';
				let d = (p.length && b.length) ? ` && ` : '';
				return (s.length && b.length > 5) ? `(${s})${a}(${p}${d}${b})` : s.length ? `(${s})${a}(${p})` : b.length ? `(${b})` : 'false';
			};
			let conf5 = () => {
				return leakS('phase0', 'phase0', false, true, false) || 'false';
			};
			quer = quer.concat([
				`(* Message ${abc}: Authentication sanity *)`,
				`\tevent(RecvMsg(${recv}, ${send}, stagepack_${abc}(${recvsid}), m)) ==> (event(SendMsg(${send}, ${recv}, stagepack_${abc}(${sendsid}), m)));`,
				`(* Message ${abc}: Authentication 1 *)`,
				`\tevent(RecvMsg(${recv}, ${send}, stagepack_${abc}(${recvsid}), m)) ==> (event(SendMsg(${send}, c, stagepack_${abc}(${sendsid}), m))) || (${leakS('phase0', 'phase0', true, true, false) || 'false'}) || (${leakS('phase0', 'phase0', false, true) || 'false'});`,
				`(* Message ${abc}: Authentication 2 *)`,
				`\tevent(RecvMsg(${recv}, ${send}, stagepack_${abc}(${recvsid}), m)) ==> (event(SendMsg(${send}, c, stagepack_${abc}(${sendsid}), m))) || (${leakS('phase0', 'phase0', true, true, false) || 'false'});`,
				`(* Message ${abc}: Authentication 3 *)`,
				`\tevent(RecvMsg(${recv}, ${send}, stagepack_${abc}(${recvsid}), m)) ==> (event(SendMsg(${send}, ${recv}, stagepack_${abc}(${sendsid}), m))) || (${leakS('phase0', 'phase0', true, true, false) || 'false'}) || (${leakS('phase0', 'phase0', false, true) || 'false'});`,
				`(* Message ${abc}: Authentication 4 *)`,
				`\tevent(RecvMsg(${recv}, ${send}, stagepack_${abc}(${recvsid}), m)) ==> (event(SendMsg(${send}, ${recv}, stagepack_${abc}(${sendsid}), m))) || (${leakS('phase0', 'phase0', true, true, false) || 'false'});`
			]);
			quer = quer.concat([
				`(* Message ${abc}: Confidentiality sanity *)`,
				`\tattacker(msg_${abc}(${send}, ${recv}, ${sendsid}));`,
				`(* Message ${abc}: Confidentiality ${confQuery21} *)`,
				`\tattacker(msg_${abc}(${send}, ${recv}, ${sendsid})) ==> ${conf21()};`,
				`(* Message ${abc}: Confidentiality ${confQuery43} *)`,
				`\tattacker(msg_${abc}(${send}, ${recv}, ${sendsid})) ==> ${conf43()};`,
				`(* Message ${abc}: Confidentiality 5 *)`,
				`\tattacker(msg_${abc}(${send}, ${recv}, ${sendsid})) ==> (${conf5()});`
			]);
		});
		pattern.messages.forEach((message, i) => {
			quer = quer.concat([
				`(* Repeating keys *)`,
				`\t(* event(RepeatingKey_${util.abc[i]}(alice)); event(RepeatingKey_${util.abc[i]}(bob)); *)`
			]);
		});
		quer = quer.concat([
			`(* Protocol termination sanity *)`,
			`\tevent(RecvEnd(true)).`
		]);
		return quer;
	};

	const globals = (pattern) => {
		return [];
	};

	const initiatorFun = (pattern) => {
		let sends = preMessagesSendStatic(pattern) ? 0 : messagesSendStatic(pattern);
		let recvs = preMessagesRecvStatic(pattern) ? 0 : messagesRecvStatic(pattern);
		let hasPsk = messagesPsk(pattern) >= 0;
		let init = {
			s: preMessagesSendStatic(pattern) ?
				`generate_keypair(key_s(me))` : util.emptyKeyPair,
			e: preMessagesSendEphemeral(pattern) ?
				`generate_keypair(key_e(me, them, sid))` : `${util.emptyKeyPair}`,
			rs: preMessagesRecvStatic(pattern) ?
				`getpublickey(generate_keypair(key_s(them)))` : util.emptyKey,
			re: preMessagesRecvEphemeral(pattern) ?
				'in(pub, re:key);' : `let re = ${util.emptyKey} in`,
			psk: hasPsk ?
				'key_psk(me, them)' : util.emptyKey
		};
		let outStatic = sends >= 0 ?
			`out(pub, getpublickey(s));` : `(* No static key initialized *)`;
		let phase0End = (pattern.messages[pattern.messages.length - 1].dir === 'recv') ?
			`event RecvEnd(valid)` : `(* Not last recipient *)`;
		let initiator = [
			`let initiator(me:principal, them:principal, sid:sessionid) =`,
			`let s = ${init.s} in`,
			outStatic,
			`((`,
			`\tlet e = ${init.e} in`
		];
		let finalKex = finalKeyExchangeMessage(pattern);
		if (preMessagesSendEphemeral(pattern)) {
			initiator.push(`out(pub, getpublickey(e));`);
		}
		initiator = initiator.concat([
			`\tlet rs = ${init.rs} in`,
			`\t${init.re}`,
			`\tlet hs:handshakestate = initialize_initiator(empty, s, e, rs, re, ${init.psk}) in`,
			`\tinsert statestore(me, them, sid, statepack_${util.abc[0]}(hs))`,
			`) | (`,
		]);
		pattern.messages.forEach((message, i) => {
			let msgDirSend = (message.dir === 'send');
			let abc = util.abc[i];
			let abcn = util.abc[i + 1];
			let isFinal = (i === finalKex);
			let nextMessage = pattern.messages[i + 1] ?
				(pattern.messages[i + 1].tokens.length ? ' | (' : ' | !(') : ' | (';
			let splitCipherState = isFinal ?
				`, cs1:cipherstate, cs2:cipherstate` : ``;
			let statePack = (i <= finalKex) ? `get statestore(=me, =them, =sid, statepack_${abc}(hs)) in` : [
				`get statestore(=me, =them, =sid, statepack_${abc}(hs, cs1, cs2)) in`,
				`let hs = handshakestatesetcs(hs, ${msgDirSend? 'cs1' : 'cs2'}) in`
			].join('\n\t\t');
			let statePackNext = (i < finalKex) ?
				`statepack_${abcn}(hs)` :
				`statepack_${abcn}(hs, ${isFinal? 'cs1, cs2' :
					(msgDirSend? 'handshakestategetcs(hs), cs2' : 'cs1, handshakestategetcs(hs)')})`;
			let stateStore = (i < (pattern.messages.length - 1)) ?
				`insert statestore(me, them, sid, ${statePackNext});` :
				`(* Final message, do not pack state *)`;
			if (msgDirSend) {
				initiator = initiator.concat([
					`\t${statePack}`,
					`\tlet (hs:handshakestate, message_${abc}:bitstring${splitCipherState}) = writeMessage_${abc}(me, them, hs, msg_${abc}(me, them, sid), sid) in`,
					`\tevent SendMsg(me, them, stagepack_${abc}(sid), msg_${abc}(me, them, sid));`,
					`\t${stateStore}`,
					`\tout(pub, message_${abc})`,
					`)${nextMessage}`
				]);
			} else {
				initiator = initiator.concat([
					`\t${statePack}`,
					`\tin(pub, message_${abc}:bitstring);`,
					`\tlet (hs:handshakestate, plaintext_${abc}:bitstring, valid:bool${splitCipherState}) = readMessage_${abc}(me, them, hs, message_${abc}, sid) in`,
					`\tevent RecvMsg(me, them, stagepack_${abc}(sid), plaintext_${abc});`,
					`\t${stateStore}`,
					(i === (pattern.messages.length - 1)) ? `\t${phase0End}` : `\t0`,
					`)${nextMessage}`
				]);
			}
		});
		if (hasPsk) {
			initiator = initiator.concat([
				`\tevent LeakPsk(phase0, me, them);`,
				`\tout(pub, key_psk(me, them))`,
				`) | (`,
				`\tphase 1;`,
				`\tevent LeakPsk(phase1, me, them);`,
				`\tout(pub, key_psk(me, them))`,
				`) | (`
			]);
		}
		if (sends >= 0) {
			initiator = initiator.concat([
				`\tevent LeakS(phase0, me);`,
				`\tout(pub, key_s(me))`,
				`) | (`,
				`\tphase 1;`,
				`\tevent LeakS(phase1, me);`,
				`\tout(pub, key_s(me))`,
				`)).`
			]);
		} else {
			initiator.push('0)).');
		}
		return initiator;
	};

	const responderFun = (pattern) => {
		let sends = preMessagesSendStatic(pattern) ? 0 : messagesSendStatic(pattern);
		let recvs = preMessagesRecvStatic(pattern) ? 0 : messagesRecvStatic(pattern);
		let hasPsk = messagesPsk(pattern) >= 0;
		let init = {
			s: preMessagesRecvStatic(pattern) ?
				`generate_keypair(key_s(me))` : util.emptyKeyPair,
			e: preMessagesRecvEphemeral(pattern) ?
				`generate_keypair(key_e(me, them, sid))` : `${util.emptyKeyPair}`,
			rs: preMessagesSendStatic(pattern) ?
				`getpublickey(generate_keypair(key_s(them)))` : util.emptyKey,
			re: preMessagesSendEphemeral(pattern) ?
				'in(pub, re:key);' : `let re = ${util.emptyKey} in`,
			psk: hasPsk ?
				'key_psk(them, me)' : util.emptyKey
		};
		let outStatic = recvs >= 0 ?
			`out(pub, getpublickey(s));` : `(* No static key initialized *)`;
		let phase0End = (pattern.messages[pattern.messages.length - 1].dir === 'send') ?
			`event RecvEnd(valid)` : `(* Not last recipient *)`;
		let responder = [
			`let responder(me:principal, them:principal, sid:sessionid) =`,
			`let s = ${init.s} in`,
			outStatic,
			`((`,
			`\tlet e = ${init.e} in`
		];
		let finalKex = finalKeyExchangeMessage(pattern);
		if (preMessagesRecvEphemeral(pattern)) {
			responder.push(`out(pub, getpublickey(e));`);
		}
		responder = responder.concat([
			`\tlet rs = ${init.rs} in`,
			`\t${init.re}`,
			`\tlet hs:handshakestate = initialize_responder(empty, s, e, rs, re, ${init.psk}) in`,
			`\tinsert statestore(me, them, sid, statepack_${util.abc[0]}(hs))`,
			`) | (`,
		]);
		pattern.messages.forEach((message, i) => {
			let msgDirSend = (message.dir === 'send');
			let abc = util.abc[i];
			let abcn = util.abc[i + 1];
			let isFinal = (i === finalKex);
			let nextMessage = pattern.messages[i + 1] ?
				(pattern.messages[i + 1].tokens.length ? ' | (' : ' | !(') : ' | (';
			let splitCipherState = isFinal ?
				`, cs1:cipherstate, cs2:cipherstate` : ``;
			let statePack = (i <= finalKex) ? `get statestore(=me, =them, =sid, statepack_${abc}(hs)) in` : [
				`get statestore(=me, =them, =sid, statepack_${abc}(hs, cs1, cs2)) in`,
				`let hs = handshakestatesetcs(hs, ${msgDirSend? 'cs1' : 'cs2'}) in`
			].join('\n\t\t');
			let statePackNext = (i < finalKex) ?
				`statepack_${abcn}(hs)` :
				`statepack_${abcn}(hs, ${isFinal? 'cs1, cs2' :
					(msgDirSend? 'handshakestategetcs(hs), cs2' : 'cs1, handshakestategetcs(hs)')})`;
			let stateStore = (i < (pattern.messages.length - 1)) ?
				`insert statestore(me, them, sid, ${statePackNext});` :
				`(* Final message, do not pack state *)`;
			if (msgDirSend) {
				responder = responder.concat([
					`\t${statePack}`,
					`\tin(pub, message_${abc}:bitstring);`,
					`\tlet (hs:handshakestate, plaintext_${abc}:bitstring, valid:bool${splitCipherState}) = readMessage_${abc}(me, them, hs, message_${abc}, sid) in`,
					`\tevent RecvMsg(me, them, stagepack_${abc}(sid), plaintext_${abc});`,
					`\t${stateStore}`,
					(i === (pattern.messages.length - 1)) ? `\t${phase0End}` : `\t0`,
					`)${nextMessage}`
				]);
			} else {
				responder = responder.concat([
					`\t${statePack}`,
					`\tlet (hs:handshakestate, message_${abc}:bitstring${splitCipherState}) = writeMessage_${abc}(me, them, hs, msg_${abc}(me, them, sid), sid) in`,
					`\tevent SendMsg(me, them, stagepack_${abc}(sid), msg_${abc}(me, them, sid));`,
					`\t${stateStore}`,
					`\tout(pub, message_${abc})`,
					`)${nextMessage}`
				]);
			}
		});
		if (hasPsk) {
			responder = responder.concat([
				`\tevent LeakPsk(phase0, them, me);`,
				`\tout(pub, key_psk(them, me))`,
				`) | (`,
				`\tphase 1;`,
				`\tevent LeakPsk(phase1, them, me);`,
				`\tout(pub, key_psk(them, me))`,
				`) | (`
			]);
		}
		if (recvs >= 0) {
			responder = responder.concat([
				`\tevent LeakS(phase0, me);`,
				`\tout(pub, key_s(me))`,
				`) | (`,
				`\tphase 1;`,
				`\tevent LeakS(phase1, me);`,
				`\tout(pub, key_s(me))`,
				`)).`
			]);
		} else {
			responder.push('0)).');
		}
		return responder;
	};

	let repeatingKeysQueryFun = (pattern) => {
		let repeatingKeysQuery = [
			`let repeatingKeysQuery() =`,
			`(`
		];
		pattern.messages.forEach((message, i) => {
			if (message.tokens.length) {
				repeatingKeysQuery = repeatingKeysQuery.concat([
					`\tget statestore(a, b, sid_x, statepack_${util.abc[i]}(hs_x)) in`,
					`\tget statestore(c, d, sid_y, statepack_${util.abc[i]}(hs_y)) in`,
					`\tlet cs_x = handshakestategetcs(hs_x) in`,
					`\tlet cs_y = handshakestategetcs(hs_y) in`,
					`\tlet (k_x:key, n_x:nonce) = cipherstateunpack(cs_x) in`,
					`\tlet (k_y:key, n_y:nonce) = cipherstateunpack(cs_y) in`,
					`\tif ((k_x = k_y) && ((b <> c) || (a <> d)) && ((a <> c) || (b <> d) || (sid_x <> sid_y))) then (`,
					`\t\tevent RepeatingKey_${util.abc[i]}(a)`,
					`\t)`
				]);
			} else {
				let csn = (i % 2) ? '2' : '1';
				repeatingKeysQuery = repeatingKeysQuery.concat([
					`\tget statestore(a, b, sid_x, statepack_${util.abc[i]}(hs_x, cs1_x, cs2_x)) in`,
					`\tget statestore(c, d, sid_y, statepack_${util.abc[i]}(hs_y, cs1_y, cs2_y)) in`,
					`\tlet (k${csn}_x:key, n${csn}_x:nonce) = cipherstateunpack(cs${csn}_x) in`,
					`\tlet (k${csn}_y:key, n${csn}_y:nonce) = cipherstateunpack(cs${csn}_y) in`,
					`\tif ((k${csn}_x = k${csn}_y) && ((b <> c) || (a <> d)) && ((a <> c) || (b <> d) || (sid_x <> sid_y))) then (`,
					`\t\tevent RepeatingKey_${util.abc[i]}(a)`,
					`\t)`
				]);
			}
			if (i < (pattern.messages.length - 1)) {
				repeatingKeysQuery.push(') | (');
			} else {
				repeatingKeysQuery.push(').');
			}
		});
		return repeatingKeysQuery;
	};

	const processFuns = (pattern) => {
		let hasPsk = messagesPsk(pattern) >= 0;
		let proc = [
			`out(pub, key_s(charlie));`,
			`!(`,
			`\tnew sid:sessionid;`,
			`\tinitiator(alice, bob, sid) | initiator(alice, charlie, sid) |`,
			`\tresponder(bob, alice, sid) | responder(bob, charlie, sid)`,
			`\t(* | !repeatingKeysQuery() *)`
		];
		proc = proc.concat([')']);
		return proc;
	};

	const parse = (pattern, passive) => {
		let t = `set attacker = active.`
		if (passive) {
			params.attacker = 'passive';
			t = 'set attacker = passive.';
		}
		let s = typeFuns(pattern).join('\n');
		let i = initializeFuns(pattern).join('\n\n');
		let w = writeMessageFuns(pattern).join('\n\n');
		let r = readMessageFuns(pattern).join('\n\n');
		let e = events(pattern).join('\n');
		let g = globals(pattern).join('\n');
		let a = initiatorFun(pattern).join('\n\t');
		let b = responderFun(pattern).join('\n\t');
		let k = repeatingKeysQueryFun(pattern).join('\n\t');
		let p = processFuns(pattern).join('\n\t');
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
		NOISE2PV.parse = parse;
	}

})();