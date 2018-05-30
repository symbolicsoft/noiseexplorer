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
			`new key_e[me, them, sid]:key;`,
			`let e = generate_keypair(key_e) in`,
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
		`letfun writeMessage_${suffix}(me:principal, them:principal, hs:handshakestate, payload:bitstring) =`,
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
	pattern.messages.forEach((message, i) => {
		let hasPsk = /psk\d$/.test(pattern.name);
		let initiator = (message.dir === 'send');
		let isFinal = (i === (pattern.messages.length - 1));
		writeFuns.push(
			writeMessageFun(message, hasPsk, initiator, isFinal, util.abc[i])
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
		`letfun readMessage_${suffix}(me:principal, them:principal, hs:handshakestate, message:bitstring) =`,
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
	pattern.messages.forEach((message, i) => {
		let hasPsk = /psk\d$/.test(pattern.name);
		let initiator = (message.dir === 'recv');
		let isFinal = (i === (pattern.messages.length - 1));
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
		let end = (i < (pattern.messages.length - 1))? ';' : '.';
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
	// quer.push(`\tevent(RecvEnd(true)).`);
	return quer;
};

const globals = (pattern) => {
	return [];
};

const initiatorFun = (pattern) => {
	let init = {
		s: preMessagesSendStatic(pattern)?
			`generate_keypair(key_s(me))` : util.emptyKeyPair,
		e: preMessagesSendEphemeral(pattern)? [
			`new key_e[me, them, sid]:key;`,
			`let e = generate_keypair(key_e) in`
		].join('\n\t') : `let e = ${util.emptyKeyPair} in`,
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
		`${init.e}`
	];
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
		let abc = util.abc[i];
		let abcn = util.abc[i + 1];
		let replicateMessage = message.tokens.length? '' : '!';
		let splitCipherState = (i === (pattern.messages.length - 1))?
			`, cs1:cipherstate, cs2:cipherstate` : ``;
		if (message.dir === 'send') {
			initiator = initiator.concat([
				`| ${replicateMessage}(`,
				`\tget statestore(=me, =them, statepack_${abc}(hs)) in`,
				`\tlet (hs:handshakestate, re:key, message_${abc}:bitstring${splitCipherState}) = writeMessage_${abc}(me, them, hs, msg_${abc}(me, them)) in`,
				`\tevent SendMsg(me, them, stage_${abc}(sid), msg_${abc}(me, them), true);`,
				`\tinsert statestore(me, them, statepack_${abcn}(hs));`,
				`\tout(pub, message_${abc})`,
				`)`
			]);
		} else if (message.dir === 'recv') {
			initiator = initiator.concat([
				`| ${replicateMessage}(`,
				`\tget statestore(=me, =them, statepack_${abc}(hs)) in`,
				`\tin(pub, message_${abc}:bitstring);`,
				`\tlet (hs:handshakestate, re:key, plaintext_${abc}:bitstring, valid:bool${splitCipherState}) = readMessage_${abc}(me, them, hs, message_${abc}) in`,
				`\tevent RecvMsg(me, them, stage_${abc}(sid), plaintext_${abc}, valid);`,
				`\tinsert statestore(me, them, statepack_${abcn}(hs));`,
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
		e: preMessagesRecvEphemeral(pattern)? [
			`new key_e[me, them]:key;`,
			`let e = generate_keypair(key_e) in`
		].join('\n\t') : `let e = ${util.emptyKeyPair} in`,
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
		`${init.e}`
	];
	if (preMessagesRecvEphemeral(pattern)) {
		responder.push(`out(pub, getpublickey(e));`);
	}
	responder = responder.concat([
		`\tlet rs = ${init.rs} in`,
		`\t${init.re}`,
		`\tlet hs:handshakestate = initialize_b(empty, s, e, rs, re, ${init.psk}) in`,
		`\tinsert statestore(me, them, statepack_a(hs))`,
		`)`
	]);
	pattern.messages.forEach((message, i) => {
		let abc = util.abc[i];
		let abcn = util.abc[i + 1];
		let replicateMessage = message.tokens.length? '' : '!';
		let splitCipherState = (i === (pattern.messages.length - 1))?
			`, cs1:cipherstate, cs2:cipherstate` : ``;
		if (message.dir === 'recv') {
			responder = responder.concat([
				`| ${replicateMessage}(`,
				`\tget statestore(=me, =them, statepack_${abc}(hs)) in`,
				`\tlet (hs:handshakestate, re:key, message_${abc}:bitstring${splitCipherState}) = writeMessage_${abc}(me, them, hs, msg_${abc}(me, them)) in`,
				`\tevent SendMsg(me, them, stage_${abc}(sid), msg_${abc}(me, them), true);`,
				`\tinsert statestore(me, them, statepack_${abcn}(hs));`,
				`\tout(pub, message_${abc})`,
				`)`
			]);
		} else if (message.dir === 'send') {
			responder = responder.concat([
				`| ${replicateMessage}(`,
				`\tget statestore(=me, =them, statepack_${abc}(hs)) in`,
				`\tin(pub, message_${abc}:bitstring);`,
				`\tlet (hs:handshakestate, re:key, plaintext_${abc}:bitstring, valid:bool${splitCipherState}) = readMessage_${abc}(me, them, hs, message_${abc}) in`,
				`\tevent RecvMsg(me, them, stage_${abc}(sid), plaintext_${abc}, valid);`,
				`\tinsert statestore(me, them, statepack_${abcn}(hs));`,
				(i === (pattern.messages.length - 1))? `\t${phase0End}` : `\t0`,
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
	let i = initializeFuns(pattern).join('\n\n');
	let w = writeMessageFuns(pattern).join('\n\n');
	let r = readMessageFuns(pattern).join('\n\n');
	let e = events(pattern).join('\n');
	let g = globals(pattern).join('\n');
	let a = initiatorFun(pattern).join('\n\t');
	let b = responderFun(pattern).join('\n\t');
	let p = processFuns(pattern).join('\n\t');
	let q = queries(pattern).join('\n');
	let parsed = {t, i, w, r, e, q, g, a, b, p};
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