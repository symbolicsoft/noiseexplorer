{
	const g = {
		s: 0,
		e: 0,
		rs: 0,
		re: 0
	};

	const util = {
		hasDuplicates: (arr) => {
			let vo = {};
			for (let i = 0; i < arr.length; ++i) {
				let v = arr[i];
				if (v in vo) { return true; }
				vo[v] = true;
			}
			return false;
		}
	};

	const check = {
		preMessages: (pattern) => {
			pattern.preMessages.forEach((preMessage) => {
				let arg = '';
				if (preMessage.dir === 'recv') {
					arg = 'r';
				}
				if (preMessage.tokens === 'e, s') {
					arg = `${arg}e, `;
					if (preMessage.dir === 'recv') {
						arg = `${arg}r`
					}
					arg = `${arg}s`;
				} else {
					arg = `${arg}${preMessage.tokens}`;
				}
				let initialized = false;
				pattern.args.forEach((i) => {
					if (i.tokens === arg) {
						initialized = true;
					}
				});
				if (!initialized) {
					error(errMsg.keyNotInitialized);
				}
				if (preMessage.tokens.indexOf('s') >= 0) {
					if (preMessage.dir === 'send') {
						g.s  = g.s + 1;
					} else {
						g.rs = g.rs + 1;
					}
				}
				if (preMessage.tokens.indexOf('e') >= 0) {
					if (preMessage.dir === 'send') {
						g.e  = g.e + 1;
					} else {
						g.re = g.re + 1;
					}
				}
			});
		},
		messages: (pattern) => {
			if (pattern.messages.length > 8) {
				error(errMsg.tooManyMessages);
			}
			pattern.messages.forEach((message, i) => {
				if (
					((i % 2)  && (message.dir === 'send')) ||
					(!(i % 2) && (message.dir === 'recv'))
				) {
					error(errMsg.wrongMessageDir);
				}
				if (util.hasDuplicates(message.tokens)) {
					error(errMsg.dupTokens);
				}
				if (message.tokens.length > 8) {
					error(errMsg.tooManyTokens);
				}
				if (message.tokens.indexOf('s') >= 0) {
					if (message.dir === 'send') {
						g.s  = g.s + 1;
					} else {
						g.rs = g.rs + 1;
					}
				}
				if (message.tokens.indexOf('e') >= 0) {
					if (message.dir === 'send') {
						g.e  = g.e + 1;
					} else {
						g.re = g.re + 1;
					}
				}
			});
		},
		psk: (pattern) => {
			let pskMods = pattern.name.match(/psk\d/g);
			if (pskMods) {
				if (pskMods.length > 1) {
					error(errMsg.moreThanOnePsk);
				}
				if (!/psk\d$/.test(pattern.name)) {
					error(errMsg.pskNotAtEndOfName);
				}
				pskMods.forEach((pskMod) => {
					pskMod = parseInt(pskMod.charAt(3), 10);
					if (pskMod > pattern.messages.length) {
						error(errMsg.wrongPskModifier);
					} else if (pskMod === 0) {
						let tokens = pattern.messages[pskMod].tokens;
						if (tokens.indexOf('psk') < 0) {
							error(errMsg.wrongPskModifier);
						} else if (tokens.indexOf('psk') > 0) {
							error(errMsg.wrongPskLocation);
						}
					} else {
						let tokens = pattern.messages[pskMod - 1].tokens;
						if (tokens.indexOf('psk') < 0) {
							error(errMsg.wrongPskModifier);
						} else if (tokens.indexOf('psk') !== (tokens.length - 1)) {
							(pskMod === 1)? error(errMsg.wrongPskModifier) : error(errMsg.wrongPskLocation);
						}
					}
				});
			} else {
				pattern.messages.forEach((message) => {
					if (message.tokens.indexOf('psk') > 0) {
						error(errMsg.wrongPskModifier);
					}
				});
			}
		},
		tokenlessMessages: (pattern) => {
			let tokenlessMessage = -1;
			pattern.messages.forEach((message, i) => {
				if (
					(message.tokens.length === 0) &&
					(tokenlessMessage === -1)
				) {
					tokenlessMessage = i;
				}
				if (
					(message.tokens.length > 0) &&
					(tokenlessMessage >= 0) &&
					(i > tokenlessMessage)
				) {
					error(errMsg.tokenlessNotLast);
				}
			});
		}
	};

	const errMsg = {
		tooLongName: 'Handshake pattern names with a maximum length of 16 characters are currently supported.',
		tooManyTokens: 'Message patterns with a maximum of 8 tokens are currently supported.',
		tooManyMessages: 'Handshake patterns with a maximum of 8 message patterns are currently supported.',
		dupTokens: 'Noise pattern must not contain duplicate tokens in the same message flight.',
		keyNotInitialized: 'Parties can only send a static public key if they were initialized with a static key pair, and can only perform DH between private keys and public keys they possess.',
		keySentMoreThanOnce: 'Parties must not send their static public key or ephemeral public key more than once per handshake.',
		wrongPskModifier: 'PSK modifiers must correctly indicate the position of PSK tokens.',
		wrongPskLocation: 'PSK tokens must appear at the beginning or end of the first handshake message or at the end of any other handshake message.',
		moreThanOnePsk: 'Handshake patterns with a maximum of one PSK are currently supported.',
		pskNotAtEndOfName: 'PSK modifiers must appear at the end of the Noise handshake pattern name.',
		wrongMessageDir: 'Message patterns must alternate (initiator -> responder, initiator <- responder), with the first message being sent by the initiator.',
		tokenlessNotLast: 'Noise handshake patterns can only contain tokenless handshake messages at the very bottom of the pattern.'
	};
}

Pattern =
	Name:Identifier '(' Args:Args? '):' _
    PreMessages:PreMessages? _
    Messages:Messages {
		let pattern = {
			name: Name,
			args: [],
			preMessages: [],
			messages: Messages
		};
		pattern.args = Args? Args : [];
		pattern.preMessages = PreMessages? PreMessages : [];
		check.preMessages(pattern);
		check.messages(pattern);
		check.psk(pattern);
		check.tokenlessMessages(pattern);
		if ((g.s > 1) || (g.e > 1) ||
			(g.rs > 1) || (g.re > 1)
		) {
			error(errMsg.keySentMoreThanOnce);
		}
    	return pattern;
    }

Identifier =
	[a-zA-Z0-9]+ {
		if (text().length > 16) {
			error(errMsg.tooLongName);
		} else {
			return text();
		}
	}

_  =
	[ \t\n\r]* {
		return text();
	}

Ellipsis =
	_ '...' _ {
		return (text().length > 0)
	}

Arrow =
	'->' {
		return 'send';
	} /
	'<-' {
		return 'recv';
	}

Token =
	('psk' / 'rs' / 'es' / 'se' / 'ss' / 'ee' / 's' / 'e') {
		return text();
	}

PreMessageToken =
	('e, s' / 'e' / 's') {
		return text();
	}

ArgTokenSend =
	('e, s' / 'e' / 's') {
		return text();
	}

ArgTokenRecv =
	('re, rs' / 're' / 'rs') {
		return text();
	}
    
Tokens =
	(Token (', ' / ','))* Token {
		let normalized = text().replace(/\,\s/g, ',');
		return normalized.split(',');
	}

Args =
	Args:(ArgTokenSend _ ','? _ ArgTokenRecv?) {
		let a = [{
			type: 'Arg',
			dir: 'send',
			tokens: Args[0]
		}];
		if (Args[4]) {
			a.push({
				type: 'Arg',
				dir: 'recv',
				tokens: Args[4]
			});
		}
		return a;
	} /
	Args:(ArgTokenRecv _ ','? _ ArgTokenSend?) {
		let a = [{
			type: 'Arg',
			dir: 'recv',
			tokens: Args[0]
		}];
		if (Args[4]) {
			a.unshift({
				type: 'Arg',
				dir: 'send',
				tokens: Args[4]
			});
		}
		return a;
	}
    
PreMessage =
	_ Dir:Arrow _ Token:PreMessageToken {
		return {
			type: 'PreMessage',
			dir: Dir,
			tokens: Token
		};
	}

PreMessages =
	PreMessages:((PreMessage _) (PreMessage _)? Ellipsis) {
		let pMsg = [PreMessages[0][0]];
		if (!Array.isArray(PreMessages[1])) {
			// Do nothing.
		} else if (PreMessages[1][0].dir === 'recv') {
			pMsg.push(PreMessages[1][0]);
		} else if (PreMessages[1][0].dir === 'send') {
			pMsg.unshift(PreMessages[1][0]);
		}
		return pMsg;
	}
    
Message =
	_ Dir:Arrow _ Tokens:Tokens? {
		return {
			type: 'Message',
			dir: Dir,
			tokens: Tokens? Tokens : []
		};
	}

Messages =
	Messages:(Message _)+ {
		let msgs = [];
		Messages.forEach((msg, i) => {
			msgs.push(msg[0]);
		});
		return msgs;
	}
