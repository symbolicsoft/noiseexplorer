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
	let r = false;
	pattern.messages.forEach((message) => {
		if (
			(message.dir === 'send') &&
			(message.tokens.indexOf('s') >= 0)
		) {
			r = true;
		}
	});
	return r;
};

const messagesRecvStatic = (pattern) => {
	let r = false;
	pattern.messages.forEach((message) => {
		if (
			(message.dir === 'recv') &&
			((message.tokens.indexOf('s') >= 0))
		) {
			r = true;
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
	let stage = [];
	let state = [];
	let msg = [];
	pattern.messages.forEach((message, i) => {
		let abc = util.abc[i];
		stage.push(`fun stage_${abc}(sessionid):stage [data].`);
		if (message.tokens.length) {
			state.push(`fun statepack_${abc}(handshakestate):state [data].`);
		}
		else {
			state.push(`fun statepack_${abc}(handshakestate, cipherstate, cipherstate):state [data].`);
		}
		msg.push(`fun msg_${abc}(principal, principal):bitstring [private].`);
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
			dir = (dir === 'send')? 'recv' : 'send';
		}
		initFun.push(preMessageTokenParsers[dir][preMessage.tokens]);
	});
	initFun.push(`handshakestatepack(ss, s, e, rs, re, psk, ${initiator}).`);
	return initFun.join('\n\t');
};

const initializeFuns = (pattern) => {
	return [
		initializeFun(pattern, true, util.abc[0]),
		initializeFun(pattern, false, util.abc[1])
	];
};

const writeMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
	let ePskFill = hasPsk?
		`let ss = mixKey(ss, getpublickey(e)) in` : `(* No PSK, so skipping mixKey. *)`;
	let esInitiatorFill = initiator?
		`let ss = mixKey(ss, dh(e, rs)) in` : `let ss = mixKey(ss, dh(s, re)) in`;
	let seInitiatorFill = initiator?
		`let ss = mixKey(ss, dh(s, re)) in` : `let ss = mixKey(ss, dh(e, rs)) in`;
	let finalFill = isFinal? [
		`let (ssi:symmetricstate, cs1:cipherstate, cs2:cipherstate) = split(ss) in`,
		`(hs, re, message_buffer, cs1, cs2).`
	] : [
		`(hs, re, message_buffer).`
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
			`let (ss:symmetricstate, ciphertext1:bitstring) = encryptAndHash(ss, key2bit(getpublickey(s))) in`
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
		].join(`\n\t`),
	};
	let writeFun = [
		`letfun writeMessage_${suffix}(me:principal, them:principal, hs:handshakestate, payload:bitstring, sid:sessionid) =`,
		`let (ss:symmetricstate, s:keypair, e:keypair, rs:key, re:key, psk:key, initiator:bool) = handshakestateunpack(hs) in`,
		`let (ne:bitstring, ciphertext1:bitstring, ciphertext2:bitstring) = (empty, empty, empty) in`
	];
	message.tokens.forEach((token) => {
		writeFun.push(messageTokenParsers[token]);
	});
	writeFun = writeFun.concat([
		`let (ss:symmetricstate, ciphertext2:bitstring) = encryptAndHash(ss, payload) in`,
		`let hs = handshakestatepack(ss, s, e, rs, re, psk, initiator) in`,
		`let message_buffer = concat3(ne, ciphertext1, ciphertext2) in`,
	]);
	writeFun = writeFun.concat(finalFill);
	return writeFun.join('\n\t');
};

const writeMessageFuns = (pattern) => {
	let writeFuns = [];
	let finalKex = finalKeyExchangeMessage(pattern);
	pattern.messages.forEach((message, i) => {
		let hasPsk = /psk\d$/.test(pattern.name);
		let initiator = (message.dir === 'send');
		writeFuns.push(
			writeMessageFun(message, hasPsk, initiator, (i === finalKex), util.abc[i])
		);
	});
	return writeFuns;
};

const readMessageFun = (message, hasPsk, initiator, isFinal, suffix) => {
	let ePskFill = hasPsk?
		`let ss = mixKey(ss, re) in` : `(* No PSK, so skipping mixKey. *)`;
	let esInitiatorFill = initiator?
		`let ss = mixKey(ss, dh(e, rs)) in` : `let ss = mixKey(ss, dh(s, re)) in`;
	let seInitiatorFill = initiator?
		`let ss = mixKey(ss, dh(s, re)) in` : `let ss = mixKey(ss, dh(e, rs)) in`;
	let authStaticKey = (message.tokens.indexOf('s') >= 0)?
		` && (rs = getpublickey(generate_keypair(key_s(them))))` : ``;
	let finalFill = isFinal? [
		`\tlet (ssi:symmetricstate, cs1:cipherstate, cs2:cipherstate) = split(ss) in`,
		`\t(hs, getpublickey(e), plaintext2, true, cs1, cs2)`
	] : [
		`\t(hs, getpublickey(e), plaintext2, true)`
	];
	let messageTokenParsers = {
		e: [
			`let re = bit2key(ne) in`,
			`let ss = mixHash(ss, key2bit(re)) in`,
			ePskFill
		].join(`\n\t`),
		s: [
			`let (ss:symmetricstate, plaintext1:bitstring, valid1:bool) = decryptAndHash(ss, ciphertext1) in`,
			`let rs = bit2key(plaintext1) in`
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
		].join(`\n\t`),
	};
	let readFun = [
		`letfun readMessage_${suffix}(me:principal, them:principal, hs:handshakestate, message:bitstring, sid:sessionid) =`,
		`let (ss:symmetricstate, s:keypair, e:keypair, rs:key, re:key, psk:key, initiator:bool) = handshakestateunpack(hs) in`,
		`let (ne:bitstring, ciphertext1:bitstring, ciphertext2:bitstring) = deconcat3(message) in`,
		`let valid1 = true in`
	];
	message.tokens.forEach((token) => {
		readFun.push(messageTokenParsers[token]);
	});
	readFun = readFun.concat([
		`let (ss:symmetricstate, plaintext2:bitstring, valid2:bool) = decryptAndHash(ss, ciphertext2) in`,
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
		let hasPsk = /psk\d$/.test(pattern.name);
		let initiator = (message.dir === 'recv');
		readFuns.push(
			readMessageFun(message, hasPsk, initiator, (i === finalKex), util.abc[i])
		);
	});
	return readFuns;
};

const events = (pattern) => {
	let ev = [
		'event Error().',
		'event SendEnd(bool).',
		'event RecvEnd(bool).',
		'event SendMsg(principal, principal, stage, bitstring, bool).',
		'event RecvMsg(principal, principal, stage, bitstring, bool).',
		'event LeakS(phasen, principal).',
		'event LeakPsk(phasen, key).'
	];
	return ev;
};

const queries = (pattern) => {
	let hasPsk = /psk\d$/.test(pattern.name);
	let quer = [
		`query c:principal, m:bitstring, s:sessionid, p:phasen;`,
	];
	pattern.messages.forEach((message, i) => {
		let send = (i % 2)? 'bob' : 'alice';
		let recv = (i % 2)? 'alice' : 'bob';
		let abc = util.abc[i];
		let confQuery21 = (params.attacker === 'active')? '2' : '1';
		let confQuery43 = (params.attacker === 'active')? '4' : '3';
		let end = (i < (pattern.messages.length - 1))? ';' : ';';
		quer = quer.concat([
			`(* Message ${abc}: Authenticity sanity *)`,
			`\tevent(RecvMsg(${recv}, ${send}, stage_${abc}(s), m, true)) ==> (event(SendMsg(${send}, ${recv}, stage_${abc}(s), m, true)));`,
			`(* Message ${abc}: Authenticity 1 *)`,
			`\tevent(RecvMsg(${recv}, ${send}, stage_${abc}(s), m, true)) ==> (event(SendMsg(${send}, c, stage_${abc}(s), m, true))) || (event(LeakS(phase0, ${send})) || event(LeakS(phase0, ${recv})));`,
			`(* Message ${abc}: Authenticity 2 *)`,
			`\tevent(RecvMsg(${recv}, ${send}, stage_${abc}(s), m, true)) ==> (event(SendMsg(${send}, c, stage_${abc}(s), m, true))) || (event(LeakS(phase0, ${send})));`,
			`(* Message ${abc}: Authenticity 3 *)`,
			`\tevent(RecvMsg(${recv}, ${send}, stage_${abc}(s), m, true)) ==> (event(SendMsg(${send}, ${recv}, stage_${abc}(s), m, true))) || (event(LeakS(phase0, ${send})) || event(LeakS(phase0, ${recv})));`,
			`(* Message ${abc}: Authenticity 4 *)`,
			`\tevent(RecvMsg(${recv}, ${send}, stage_${abc}(s), m, true)) ==> (event(SendMsg(${send}, ${recv}, stage_${abc}(s), m, true))) || (event(LeakS(phase0, ${send})));`
		]);
		if (hasPsk) {
		}
		quer = quer.concat([
			`(* Message ${abc}: Confidentiality sanity *)`,
			`\tattacker(msg_${abc}(${send}, ${recv}));`,
			`(* Message ${abc}: Confidentiality ${confQuery21} *)`,
			`\tattacker(msg_${abc}(${send}, ${recv})) ==> (event(LeakS(phase0, ${recv}))) || (event(LeakS(phase1, ${recv})));`,
			`(* Message ${abc}: Confidentiality ${confQuery43} *)`,
			`\tattacker(msg_${abc}(${send}, ${recv})) ==> (event(LeakS(phase0, ${recv}))) || ((event(LeakS(phase1, ${recv})) && event(LeakS(p, ${send}))));`,
			`(* Message ${abc}: Confidentiality 5 *)`,
			`\tattacker(msg_${abc}(${send}, ${recv})) ==> (event(LeakS(phase0, ${recv})))${end}`
		]);
		if (hasPsk) {
		}
	});
	quer.push(`\tevent(RecvEnd(true)).`);
	return quer;
};

const globals = (pattern) => {
	return [];
};

const initiatorFun = (pattern) => {
	let init = {
		s: preMessagesSendStatic(pattern)?
			`generate_keypair(key_s(me))` : util.emptyKeyPair,
		e: preMessagesSendEphemeral(pattern)?
			`generate_keypair(key_e(me, them, sid))` : `${util.emptyKeyPair}`,
		rs: preMessagesRecvStatic(pattern)?
			`getpublickey(generate_keypair(key_s(them)))` : util.emptyKey,
		re: preMessagesRecvEphemeral(pattern)?
			'in(pub, re:key);': `let re = ${util.emptyKey} in`,
		psk: /psk/.test(pattern.name)?
			'key_psk' : util.emptyKey
	};
	let outStatic = (preMessagesSendStatic(pattern) || messagesSendStatic(pattern))?
		`out(pub, getpublickey(s));` : `(* No static key initialized. *)`;
	let phase0End = (pattern.messages[pattern.messages.length - 1].dir === 'recv')?
		`event RecvEnd(valid)` : `(* Not last recipient. *)`;
	let initiator = [
		`let initiator(me:principal, them:principal, sid:sessionid) =`,
		`let s = ${init.s} in`,
		outStatic,
		`((`,
		`let e = ${init.e} in`
	];
	let finalKex = finalKeyExchangeMessage(pattern);
	if (preMessagesSendEphemeral(pattern)) {
		initiator.push(`out(pub, getpublickey(e));`);
	}
	initiator = initiator.concat([
		`\tlet rs = ${init.rs} in`,
		`\t${init.re}`,
		`\tlet hs:handshakestate = initialize_a(empty, s, e, rs, re, ${init.psk}) in`,
		`\tinsert statestore(me, them, statepack_${util.abc[0]}(hs))`,
		`)`
	]);
	pattern.messages.forEach((message, i) => {
		let msgDirSend = (message.dir === 'send');
		let abc = util.abc[i];
		let abcn = util.abc[i + 1];
		let replicateMessage = message.tokens.length? '' : '!';
		let splitCipherState = (i === finalKex)?
			`, cs1:cipherstate, cs2:cipherstate` : ``;
		let statePack = (i <= finalKex)? `get statestore(=me, =them, statepack_${abc}(hs)) in` : [
			`get statestore(=me, =them, statepack_${abc}(hs, cs1, cs2)) in`,
			`let hs = handshakestatesetcs(hs, ${msgDirSend? 'cs1' : 'cs2'}) in`
		].join('\n\t\t');
		let statePackNext = (i < finalKex)?
			`statepack_${abcn}(hs)` :
				`statepack_${abcn}(hs, ${(i === finalKex)? 'cs1, cs2' : (msgDirSend? 'handshakestategetcs(hs), cs2' : 'cs1, handshakestategetcs(hs)')})`;
		let stateStore = (i < (pattern.messages.length - 1))?
			`insert statestore(me, them, ${statePackNext});`
				: `(* Final message, do not pack state. *)`;
		if (msgDirSend) {
			initiator = initiator.concat([
				`| ${replicateMessage}(`,
				`\t${statePack}`,
				`\tlet (hs:handshakestate, re:key, message_${abc}:bitstring${splitCipherState}) = writeMessage_${abc}(me, them, hs, msg_${abc}(me, them), sid) in`,
				`\tevent SendMsg(me, them, stage_${abc}(sid), msg_${abc}(me, them), true);`,
				`\t${stateStore}`,
				`\tout(pub, message_${abc})`,
				`)`
			]);
		} else {
			initiator = initiator.concat([
				`| ${replicateMessage}(`,
				`\t${statePack}`,
				`\tin(pub, message_${abc}:bitstring);`,
				`\tlet (hs:handshakestate, re:key, plaintext_${abc}:bitstring, valid:bool${splitCipherState}) = readMessage_${abc}(me, them, hs, message_${abc}, sid) in`,
				`\tevent RecvMsg(me, them, stage_${abc}(sid), plaintext_${abc}, valid);`,
				`\t${stateStore}`,
				(i === (pattern.messages.length - 1))? `\t${phase0End}` : `\t0`,
				`)`
			]);
		}
	});
	initiator = initiator.concat([
		`| (`,
		`\tevent LeakS(phase0, me);`,
		`\tout(pub, key_s(me))`,
		`)`,
		`| (`,
		`\tphase 1;`,
		`\tevent LeakS(phase1, me);`,
		`\tout(pub, key_s(me))`,
		`)).`
	]);
	return initiator;
};

const responderFun = (pattern) => {
	let init = {
		s: preMessagesRecvStatic(pattern)?
			`generate_keypair(key_s(me))` : util.emptyKeyPair,
		e: preMessagesRecvEphemeral(pattern)?
			`generate_keypair(key_e(me, them, sid))` : `${util.emptyKeyPair}`,
		rs: preMessagesSendStatic(pattern)?
			`getpublickey(generate_keypair(key_s(them)))` : util.emptyKey,
		re: preMessagesSendEphemeral(pattern)?
			'in(pub, re:key);': `let re = ${util.emptyKey} in`,
		psk: /psk/.test(pattern.name)?
			'key_psk' : util.emptyKey
	};
	let outStatic = (preMessagesRecvStatic(pattern) || messagesRecvStatic(pattern))?
		`out(pub, getpublickey(s));` : `(* No static key initialized. *)`;
	let phase0End = (pattern.messages[pattern.messages.length - 1].dir === 'send')?
		`event RecvEnd(valid)` : `(* Not last recipient. *)`;
	let responder = [
		`let responder(me:principal, them:principal, sid:sessionid) =`,
		`let s = ${init.s} in`,
		outStatic,
		`((`,
		`let e = ${init.e} in`
	];
	let finalKex = finalKeyExchangeMessage(pattern);
	if (preMessagesRecvEphemeral(pattern)) {
		responder.push(`out(pub, getpublickey(e));`);
	}
	responder = responder.concat([
		`\tlet rs = ${init.rs} in`,
		`\t${init.re}`,
		`\tlet hs:handshakestate = initialize_b(empty, s, e, rs, re, ${init.psk}) in`,
		`\tinsert statestore(me, them, statepack_${util.abc[0]}(hs))`,
		`)`
	]);
	pattern.messages.forEach((message, i) => {
		let msgDirSend = (message.dir === 'send');
		let abc = util.abc[i];
		let abcn = util.abc[i + 1];
		let replicateMessage = message.tokens.length? '' : '!';
		let splitCipherState = (i === finalKex)?
			`, cs1:cipherstate, cs2:cipherstate` : ``;
		let statePack = (i <= finalKex)? `get statestore(=me, =them, statepack_${abc}(hs)) in` : [
			`get statestore(=me, =them, statepack_${abc}(hs, cs1, cs2)) in`,
			`let hs = handshakestatesetcs(hs, ${msgDirSend? 'cs1' : 'cs2'}) in`
		].join('\n\t\t');
		let statePackNext = (i < finalKex)?
			`statepack_${abcn}(hs)` :
				`statepack_${abcn}(hs, ${(i === finalKex)? 'cs1, cs2' : (msgDirSend? 'handshakestategetcs(hs), cs2' : 'cs1, handshakestategetcs(hs)')})`;
		let stateStore = (i < (pattern.messages.length - 1))?
			`insert statestore(me, them, ${statePackNext});`
				: `(* Final message, do not pack state. *)`;
		if (msgDirSend) {
			responder = responder.concat([
				`| ${replicateMessage}(`,
				`\t${statePack}`,
				`\tin(pub, message_${abc}:bitstring);`,
				`\tlet (hs:handshakestate, re:key, plaintext_${abc}:bitstring, valid:bool${splitCipherState}) = readMessage_${abc}(me, them, hs, message_${abc}, sid) in`,
				`\tevent RecvMsg(me, them, stage_${abc}(sid), plaintext_${abc}, valid);`,
				`\t${stateStore}`,
				(i === (pattern.messages.length - 1))? `\t${phase0End}` : `\t0`,
				`)`
			]);
		} else {
			responder = responder.concat([
				`| ${replicateMessage}(`,
				`\t${statePack}`,
				`\tlet (hs:handshakestate, re:key, message_${abc}:bitstring${splitCipherState}) = writeMessage_${abc}(me, them, hs, msg_${abc}(me, them), sid) in`,
				`\tevent SendMsg(me, them, stage_${abc}(sid), msg_${abc}(me, them), true);`,
				`\t${stateStore}`,
				`\tout(pub, message_${abc})`,
				`)`
			]);
		}
	});
	responder = responder.concat([
		`| (`,
		`\tevent LeakS(phase0, me);`,
		`\tout(pub, key_s(me))`,
		`)`,
		`| (`,
		`\tphase 1;`,
		`\tevent LeakS(phase1, me);`,
		`\tout(pub, key_s(me))`,
		`)).`
	]);
	return responder;
};

const processFuns = (pattern) => {
	let hasPsk = /psk/.test(pattern.name);
	let proc = [
		`out(pub, key_s(charlie));`,
		`!(`,
		`\tnew sid:sessionid;`,
		`\tout(pub, sid);`,
		`\t(`,
		`\t\tinitiator(alice, bob, sid)`,
		`\t\t|`,
		`\t\tinitiator(alice, charlie, sid)`,
		`\t\t|`,
		`\t\tresponder(bob, alice, sid)`,
		`\t\t|`,
		`\t\tresponder(bob, charlie, sid)`,
		`\t)`
	];
	if (hasPsk) {
		proc = proc.concat([
			`\t| (`,
			`\t\tevent LeakPsk(phase0, key_psk);`,
			`\t\tout(pub, key_psk)`,
			`\t)`,
			`\t| (`,
			`\t\tphase 1;`,
			`\t\tevent LeakPsk(phase1, key_psk);`,
			`\t\tout(pub, key_psk)`,
			`\t)`
		]);
	}
	proc = proc.concat([')']);
	return proc;
};

const parse = (pattern, passive) => {
	if (passive) {
		params.attacker = 'passive';
	}
	let t = params.attacker;
	let s = typeFuns(pattern).join('\n');
	let i = initializeFuns(pattern).join('\n\n');
	let w = writeMessageFuns(pattern).join('\n\n');
	let r = readMessageFuns(pattern).join('\n\n');
	let e = events(pattern).join('\n');
	let g = globals(pattern).join('\n');
	let a = initiatorFun(pattern).join('\n\t');
	let b = responderFun(pattern).join('\n\t');
	let p = processFuns(pattern).join('\n\t');
	let q = queries(pattern).join('\n');
	let parsed = {t, s, i, w, r, e, q, g, a, b, p};
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