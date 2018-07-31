const NOISEREADER = {
	read: () => {},
	render: () => {}
};

(() => {

const util = {
	abc: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h'],
	seq: [
		'first', 'second', 'third', 'fourth',
		'fifth', 'sixth', 'seventh', 'eighth'
	]
};

const readRules = {
	rawResult: /^RESULT.+(is false|is true|cannot be proved)\.$/
};

const htmlTemplates = {
	sendMessage: (offset, msg, tokens, authenticity, confidentiality) => {
		return [
			`<line data-seclevel="${confidentiality}" x1="1" x2="248" y1="${offset}" y2="${offset}"></line>`,
			`<polyline data-seclevel="${confidentiality}" points="237 ${offset-10} 248 ${offset} 237 ${offset+10}"></polyline>`,
			`<circle data-seclevel="${authenticity}" cx="17" cy="${offset}" r="15"></circle>`,
			`<text class="msg" x="16" y="${offset+5}">${msg}</text>`,
			`<text class="tokens" x="120" y="${offset-8}">${tokens}</text>`,
		].join('\n\t\t\t\t\t');
	},
	recvMessage: (offset, msg, tokens, authenticity, confidentiality) => { 
		return [
			`<line data-seclevel="${confidentiality}" x2="248" y1="${offset}" y2="${offset}"></line>`,
			`<polyline data-seclevel="${confidentiality}" points="10 ${offset-10} 1 ${offset} 10 ${offset+10}"></polyline>`,
			`<circle data-seclevel="${authenticity}" cx="234" cy="${offset}" r="15"></circle>`,
			`<text class="msg" x="233" y="${offset+5}">${msg}</text>`,
			`<text class="tokens" x="120" y="${offset-8}">${tokens}</text>`,
		].join('\n\t\t\t\t\t');
	},
	sendPreMessage: (offset, tokens) => {
		return [
			`<line x1="1" x2="248" y1="${offset}" y2="${offset}"></line>`,
			`<polyline points="237 ${offset-10} 248 ${offset} 237 ${offset+10}"></polyline>`,
			`<text class="tokens" x="120" y="${offset-8}">${tokens}</text>`,
		].join('\n\t\t\t\t\t');
	},
	recvPreMessage: (offset, tokens) => { 
		return [
			`<line x2="248" y1="${offset}" y2="${offset}"></line>`,
			`<polyline  points="10 ${offset-10} 1 ${offset} 10 ${offset+10}"></polyline>`,
			`<text class="tokens" x="120" y="${offset-8}">${tokens}</text>`,
		].join('\n\t\t\t\t\t');
	},
	ellipsis: (offset) => {
		return [
			`\n\t\t\t\t<text class="ellipsis" x="120" y="${offset}">...</text>`,
		].join('\n');
	},
	analysisPreMessage: (dir, tokens) => {
		let who = (dir === 'send')? 'initiator' : 'responder';
		let whom = (dir === 'recv')? 'initiator' : 'responder';
		let phrases = {
			'e, s': `The ${who} is initialized with both a pre-shared ephemeral key, unique to this session, and a pre-shared long-term static key, the latter of which is assumed to be pre-authenticated out of band by the ${whom}.`,
			'e': `The ${who} is initialized with a pre-shared ephemeral key being made available to the ${whom}. This key is not assumed to be authenticated.`,
			's': `The ${who} is initialized with a pre-shared long-term static key, which is assumed to be pre-authenticated out of band by the ${whom}.`
		};
		return `<p>${phrases[tokens]}</p> \n\t\t\t`;
	},
	analysisMessage: (abc, dir, tokens, authenticity, confidentiality, sanity) => {
		let who = (dir === 'send')? 'initiator' : 'responder';
		let whom = (dir === 'recv')? 'initiator' : 'responder';
		let authPhrases = {
			0: `does not benefit from <em>sender authentication</em> and does not provide <em>message integrity</em>. It could have been sent by any party, including an active attacker`,
			1: `benefits from <em>receiver authentication</em> but is <em>vulnerable to Key Compromise Impersonation</em>. If the ${whom}'s long-term private key has been compromised, this authentication can be forged. However, if the ${who} carries out a separate session with a separate, compromised ${whom}, this other session can be used to forge the authenticity of this message with this session's ${whom}`,
			2: `benefits from <em>sender authentication</em> and is <em>resistant to Key Compromise Impersonation</em>. Assuming the corresponding private keys are secure, this authentication cannot be forged. However, if the ${who} carries out a separate session with a separate, compromised ${whom}, this other session can be used to forge the authenticity of this message with this session's ${whom}`,
			3: `benefits from <em>sender and receiver receiver authentication</em> but is <em>vulnerable to Key Compromise Impersonation</em>. If the ${whom}'s long-term private key has been compromised, this authentication can be forged`,
			4: `benefits from <em>sender and receiver authentication</em> and is <em>resistant to Key Compromise Impersonation</em>. Assuming the corresponding private keys are secure, this authentication cannot be forged`
		};
		let confPhrases = {
			0: `Message contents are sent in cleartext and do not benefit from <em>message secrecy</em> and any <em>forward secrecy</em> is out of the question`,
			1: `Message contents benefit from some <em>message secrecy</em> and some <em>forward secrecy</em>, but not sufficiently to resist any active attacker`,
			2: `Message contents benefit from <em>message secrecy</em> and some <em>forward secrecy</em>: the compromise of the ${whom}'s long-term private keys, even at a later date, will lead to message contents being decrypted by the attacker`,
			3: `Message contents benefit from <em>message secrecy</em> and <em>weak forward secrecy</em> under a passive attacker: if the ${who}'s long-term static keys were previously compromised, the later compromise of the ${whom}'s long-term static keys can lead to message contents being decrypted by an attacker`,
			4: `Message contents benefit from <em>message secrecy</em> and <em>weak forward secrecy</em> under an active attacker: if the ${who}'s long-term static keys were previously compromised, the later compromise of the ${whom}'s long-term static keys can lead to message contents being decrypted by an active attacker, should that attacker also have forged the ${whom}'s ephemeral key during the session`,
			5: `Message contents benefit from <em>message secrecy</em> and <em>strong forward secrecy</em>: if the ephemeral private keys are secure and the ${whom} is not being actively impersonated by an active attacker, message contents cannot be decrypted`
		};
		let sanPhrases = {
			true: ``,
			false: `<strong>Sanity of this result could not be verified.</strong>`
		};
		let phrase = [
			`\n\t\t\t<h3>Message ${abc.toUpperCase()} <a href="${abc.toUpperCase()}.html" class="detailedAnalysis">show detailed analysis</a></h3>`,
			`<p>Message ${abc.toUpperCase()}, sent by the ${who}, ${authPhrases[authenticity]}. ${confPhrases[confidentiality]}. ${sanPhrases[sanity]} <span class="resultNums">${authenticity},${confidentiality}</span></p>`
		].join('\n\t\t\t');
		return phrase;
	},
	detailed: {
		sendMessage: (msg, tokens, authenticity, confidentiality) => {
			return [
				`<line data-seclevel="${confidentiality}" x1="1" x2="500" y1="70" y2="70"></line>`,
				`<polyline data-seclevel="${confidentiality}" points="480,50 500,70 480,90"></polyline>`,
				`<circle data-seclevel="${authenticity}" cx="29" cy="70" r="25"></circle>`,
				`<text class="msg" x="29" y="77">${msg}</text>`,
				`<text class="tokens" x="240" y="50">${tokens}</text>`
			].join('\n\t\t\t\t\t');
		},
		recvMessage: (msg, tokens, authenticity, confidentiality) => { 
			return [
				`<line data-seclevel="${confidentiality}" x1="1" x2="500" y1="70" y2="70"></line>`,
				`<polyline data-seclevel="${confidentiality}" points="21,50 3,70 21,90"></polyline>`,
				`<circle data-seclevel="${authenticity}" cx="474" cy="70" r="25"></circle>`,
				`<text class="msg" x="474" y="77">${msg}</text>`,
				`<text class="tokens" x="240" y="50">${tokens}</text>`
			].join('\n\t\t\t\t\t');
		},
		intro: (name, abc, seq, dir) => {
			let who = (dir === 'send')? 'initiator' : 'responder';
			let whom = (dir === 'recv')? 'initiator' : 'responder';
			return `<p>Message <span class="mono">${abc.toUpperCase()}</span> is the ${seq} message in the <span class="mono">${name}</span> Noise Handshake Pattern. It is sent from the ${who} to the ${whom}. In this detailed analysis, we attempt to give you some insight into the protocol logic underlying this message. The insight given here does not fully extend down to fully illustrate the exact state transformations conducted by the formal model, but it does describe them at least informally in order to help illustrate how Message <span class="mono">${abc.toUpperCase()}</span> affects the protocol.</p>`;
		},
		tokenTxt: (abc, dir, write, token) => {
			let who = (dir === 'send')? 'initiator' : 'responder';
			let whom = (dir === 'recv')? 'initiator' : 'responder';
			let letfunName = write? `writeMessage` : `readMessage`;
			let stateFuns = {
				mixKey: (dir, dh) => {
					let dhDesc = '';
					switch (dh) {
						case 'e, re': dhDesc = `ephemeral key and the responder's ephemeral key`; break;
						case 'e, rs': dhDesc = `ephemeral key and the responder's static key`; break;
						case 's, re': dhDesc = `static key and the responder's ephemeral key`; break;
						case 's, rs': dhDesc = `static key and the responder's static key`; break;
					};
					return `<span class="mono">mixKey</span>, which calls the HKDF function using, as input, the existing <span class="mono">SymmetricState</span> key, and <span class="mono">dh(${dh})</span>, the Diffie-Hellman share calculated from the initiator's ${dhDesc}.`;
				},
				mixHash: (dir) => {
					return `<span class="mono">mixHash</span>, which hashes the new key into the session hash.`;
				},
				mixKeyAndHash: (dir) => {
					return ` <span class="mono">mixKeyAndHash</span>, which mixes and hashes the PSK value into the state and then initializes a new state seeded by the result.`;
				},
				encryptAndHash: (dir, write) => {
					return `<span class="mono">encryptAndHash</span> is called on the static public key. If any prior Diffie-Hellman shared secret was established between the sender and the recipient, this allows the ${who} to communicate their long-term identity with some degree of confidentiality.`
				},
			};
			let verb = (token.length > 1)?
				'calculating' : (write? 'sending' : 'receiving');
			let desc = (() => {
				let p = `a Diffie-Hellman shared secret derived from the initiator's`;
				switch(token) {
					case 'e': return `a fresh ephemeral key share`; break;
					case 's': return `a static key share`; break;
					case 'ee': return `${p} ephemeral key and the responder's ephemeral key`; break;
					case 'es': return `${p} ephemeral key and the responder's static key`; break;
					case 'se': return `${p} static key and the responder's ephemeral key`; break;
					case 'ss': return `${p} static key and the responder's static key`; break;
					case 'psk': return `a new session secret that adds a pre-shared symmetric key`; break;
				}
			})();
			let res = [
				`<ul>`,
				`<li><span class="mono">${token}</span>: Signals that the ${write? who : whom} is ${verb} ${desc} as part of this message. This token adds the following state transformations to <span class="mono">${letfunName}_${abc}</span>:</li>`,
				`<ul>`
			];
			switch(token) {
				case 'e': res = res.concat([
					`<li>${stateFuns.mixHash(dir)}</li>`
				]); break;
				case 's': res = res.concat([
					`<li>${stateFuns.encryptAndHash(dir, true)}</li>`
				]); break;
				case 'ee': res = res.concat([
					`<li>${stateFuns.mixKey(dir, 'e, re')}</li>`
				]); break;
				case 'es': res = res.concat([
					`<li>${stateFuns.mixKey(dir, 'e, rs')}</li>`
				]); break;
				case 'se': res = res.concat([
					`<li>${stateFuns.mixKey(dir, 's, re')}</li>`
				]); break;
				case 'ss': res = res.concat([
					`<li>${stateFuns.mixKey(dir, 's, rs')}</li>`
				]); break;
				case 'psk': res = res.concat([
					`<li>${stateFuns.mixKeyAndHash(dir)}</li>`
				]); break;
			}
			res.push('</ul></ul>');
			return res;
		},
		analysisTxt: (name, abc, seq, dir, write, letfun, tokens) => {
			let who = (dir === 'send')? 'initiator' : 'responder';
			let whom = (dir === 'recv')? 'initiator' : 'responder';
			let verb = write? 'sending' : 'receiving';
			let res = [
				`<h3>${verb[0].toUpperCase()}${verb.substr(1)} Message <span class="mono">${abc.toUpperCase()}</span></h3>`,
				`<p>In the applied pi calculus, the initiator's process prepares Message <span class="mono">${abc.toUpperCase()}</span> using the following function:</p>`,
				`<p class="proverif">`
			];
			res = res.concat(letfun.split('\n'));
			res.push(`</p>`);
			if (tokens.length) {
				res = res.concat([
					`<h4>How each token is processed by the ${write? who : whom}:</h4>`
				]);
				tokens.forEach((token) => {
					res = res.concat(htmlTemplates.detailed.tokenTxt(abc, dir, write, token))
				});
			} else {
				res = res.concat([
					`Since Message <span class="mono">${abc.toUpperCase()}</span> contains no tokens, it is considered purely an "AppData" type message meant to transfer encrypted payloads.`
				]);
			};
			if (tokens.indexOf('s') < 0) {
				res.push(`<p>If a static public key was communicated as part of this message, it would have been encrypted as <span class="mono">ciphertext1</span>. However, since the initiator does not communicate a static public key here, that value is left empty.</p>`);
			}
			res.push(`<p>Message <span class="code">${abc.toUpperCase()}</span>'s payload, which is modeled as the output of the function <span class="mono">msg_a(initiatorIdentity, responderIdentity, sessionId)</span>, is encrypted as <span class="mono">ciphertext2</span>. This invokes the following operations:</p><ul>`)
			if (write) {
				res.push(`<li><span class="mono">encryptAndHash</span>, which performs an authenticated encryption with added data (AEAD) on the payload, with the session hash as the added data (<span class="mono">encryptWithAd</span>) and <span class="mono">mixHash</span>, which hashes the encrypted payload into the next session hash.</li>`)
			} else {
				res.push(`<li><span class="mono">decryptAndHash</span>, which performs an authenticated decryption with added data (AEAD) on the payload, with the session hash as the added data (<span class="mono">decryptWithAd</span>) and <span class="mono">mixHash</span>, which hashes the encrypted payload into the next session hash.</li>`);
			}
			res.push('</ul>');
			return res.join('\n');
		}
	}
};

const getResultsTemplate = (rawResults) => {
	let resultsTemplate = {
		sanity: false
	};
	let msg = {
		authenticity: {
			sanity: false,
			one: false,
			two: false,
			three: false,
			four: false
		},
		confidentiality: {
			sanity: false,
			one: false,
			two: false,
			thour: false,
			five: false
		}
	};
	let rawResultsStr = rawResults.join('\n');
	util.abc.forEach((abc) => {
		let stage = new RegExp(`stagepack_${abc}`);
		if (stage.test(rawResultsStr)) {
			resultsTemplate[abc] = JSON.parse(JSON.stringify(msg));
		}
	});
	return resultsTemplate;
};

const getRawResults = (pvOutput) => {
	let lines = pvOutput.split('\n');
	let rawResults = [];
	lines.forEach((line) => {
		if (readRules.rawResult.test(line)) {
			rawResults.push(line);
		}
	});
	return rawResults;
};

const getMsgAbc = (rawResult) => {
	if (rawResult.match(/stagepack_\w/)) {
		return rawResult.match(/stagepack_\w/)[0][10];
	}
	if (rawResult.match(/msg_\w/)) {
		return rawResult.match(/msg_\w/)[0][4];
	}
	throw new Error('getMsgAbc failure.');
};

const getAuthenticity = (msgActive) => {
	if (!msgActive.authenticity.one) {
		return 0;
	}
	if (!msgActive.authenticity.two) {
		return 1;
	}
	if (!msgActive.authenticity.three) {
		return 2;
	}
	if (!msgActive.authenticity.four) {
		return 3;
	}
	return 4;
};

const getConfidentiality = (msgActive, msgPassive) => {
	if (!msgPassive.confidentiality.two) {
		return 0;
	}
	if (!msgActive.confidentiality.two) {
		return 1;
	}
	if (!msgPassive.confidentiality.thour) {
		return 2;
	}
	if (!msgActive.confidentiality.thour) {
		return 3;
	}
	if (!msgActive.confidentiality.five) {
		return 4;
	}
	return 5;
};

const well = (rawResult) => {
	if (rawResult.endsWith('is true.')) {
		return true;
	}
	return false;
};

const read = (pvOutput) => {
	let rawResults = getRawResults(pvOutput);
	let readResults = getResultsTemplate(rawResults);
	rawResults.forEach((rawResult, i) => {
		let isTrue = well(rawResult);
		if (i === rawResults.length - 1) {
			readResults.sanity = !isTrue;
		} else {
			let abc = getMsgAbc(rawResult);
			let r = i % 9;
			if (r === 0) {
				readResults[abc].authenticity.sanity = !isTrue;
			} else if (r === 1) {
				readResults[abc].authenticity.one = isTrue;
			} else if (r === 2) {
				readResults[abc].authenticity.two = isTrue;
			} else if (r === 3) {
				readResults[abc].authenticity.three = isTrue;
			} else if (r === 4) {
				readResults[abc].authenticity.four = isTrue;
			} else if (r === 5) {
				readResults[abc].confidentiality.sanity = !isTrue;
			} else if (r === 6) {
				readResults[abc].confidentiality.two = isTrue;
			} else if (r === 7) {
				readResults[abc].confidentiality.thour = isTrue;
			} else if (r === 8) {
				readResults[abc].confidentiality.five = isTrue;
			}
		}
	});
	return [readResults, rawResults];
};

const render = (
	pattern,
	readResultsActive, readResultsPassive,
	rawResultsActive, rawResultsPassive
) => {
	let arrowSvg = [];
	let analysisTxt = [];
	let offset = 30;
	let offsetIncrement = 185;
	if (pattern.preMessages.length) {
		pattern.preMessages.forEach((preMessage) => {
			arrowSvg.push(htmlTemplates[`${preMessage.dir}PreMessage`](
				offset, preMessage.tokens
			));
			offset = offset + offsetIncrement;
			analysisTxt.push(htmlTemplates.analysisPreMessage(
				preMessage.dir, preMessage.tokens
			));
		});
		arrowSvg.push(htmlTemplates.ellipsis(offset));
		offset = offset + offsetIncrement;
	}
	pattern.messages.forEach((message, i) => {
		let abc = util.abc[i];
		let authenticity = 0;
		let confidentiality = 0;
		let sanity = false;
		if (
			readResultsActive[abc] &&
			readResultsPassive[abc]
		) {
			authenticity = getAuthenticity(
				readResultsActive[abc]
			);
			confidentiality = getConfidentiality(
				readResultsActive[abc],
				readResultsPassive[abc]
			);
			sanity = (
				readResultsActive[abc].authenticity.sanity &&
				readResultsActive[abc].confidentiality.sanity &&
				readResultsActive.sanity
			);
			analysisTxt.push(htmlTemplates.analysisMessage(
				abc, message.dir, message.tokens,
				authenticity, confidentiality, sanity
			));
		}
		arrowSvg.push(htmlTemplates[`${message.dir}Message`](
			offset, util.abc[i],
			message.tokens.join(', '),
			authenticity,
			confidentiality
		));
		offset = offset + offsetIncrement;
	});
	return {
		arrowSvg: arrowSvg.join('\n'),
		analysisTxt: analysisTxt.join('\n'),
		offset: offset
	};
};

const renderDetailed = (
	activeModel, pattern, message,
	readResultsActive, readResultsPassive,
	rawResultsActive, rawResultsPassive
) => {
	let abc = util.abc[message];
	let seq = util.seq[message];
	let dir = pattern.messages[message].dir;
	let who = (dir === 'send')? 'alice' : 'bob';
	let whom = (dir === 'send')? 'bob' : 'alice';
	let tokens = pattern.messages[message].tokens;
	let arrowSvg = [];
	let analysisTxt = [];
	let writeMessageRegExp = new RegExp(`letfun writeMessage_${abc}[^.]+\.`, '');
	let readMessageRegExp = new RegExp(`letfun readMessage_${abc}[^.]+\.`, '');
	let writeMessage = activeModel.match(writeMessageRegExp)[0];
	let readMessage = activeModel.match(readMessageRegExp)[0];
	let authenticity = getAuthenticity(readResultsActive[abc]);
	let confidentiality = getConfidentiality(readResultsActive[abc], readResultsPassive[abc]);
	if (pattern.messages[message].dir === 'send') {
		arrowSvg.push(htmlTemplates.detailed.sendMessage(
			abc, tokens.join(', '), authenticity, confidentiality
		));
	} else {
		arrowSvg.push(htmlTemplates.detailed.recvMessage(
			abc, tokens.join(', '), authenticity, confidentiality
		));
	}
	let queryExplanations = {
		authenticity: ['',
			`In this query, we test for <em>sender authentication</em> and <em>message integrity</em>. If ${whom[0].toUpperCase()}${whom.substr(1)} receives a valid message from ${who[0].toUpperCase()}${who.substr(1)}, then ${who[0].toUpperCase()}${who.substr(1)} must have sent that message to <em>someone</em>, or ${who[0].toUpperCase()}${who.substr(1)} had their static key compromised before the session began, or ${whom[0].toUpperCase()}${whom.substr(1)} had their static key compromised before the session began.`,
			`In this query, we test for <em>sender authentication</em> and is <em>Key Compromise Impersonation</em> resistance. If ${whom[0].toUpperCase()}${whom.substr(1)} receives a valid message from ${who[0].toUpperCase()}${who.substr(1)}, then ${who[0].toUpperCase()}${who.substr(1)} must have sent that message to <em>someone</em>, or ${who[0].toUpperCase()}${who.substr(1)} had their static key compromised before the session began.`,
			`In this query, we test for <em>sender and receiver authentication</em> and <em>message integrity</em>. If ${whom[0].toUpperCase()}${whom.substr(1)} receives a valid message from ${who[0].toUpperCase()}${who.substr(1)}, then ${who[0].toUpperCase()}${who.substr(1)} must have sent that message to <em>${whom[0].toUpperCase()}${whom.substr(1)} specifically</em>, or ${who[0].toUpperCase()}${who.substr(1)} had their static key compromised before the session began, or ${whom[0].toUpperCase()}${whom.substr(1)} had their static key compromised before the session began.`,
			`In this query, we test for <em>sender and receiver authentication</em> and is <em>Key Compromise Impersonation</em> resistance. If ${whom[0].toUpperCase()}${whom.substr(1)} receives a valid message from ${who[0].toUpperCase()}${who.substr(1)}, then ${who[0].toUpperCase()}${who.substr(1)} must have sent that message to <em>${whom[0].toUpperCase()}${whom.substr(1)} specifically</em>, or ${who[0].toUpperCase()}${who.substr(1)} had their static key compromised before the session began.`,
		],
		confidentiality: ['',
			`In this query, we test for <em>message secrecy</em> by checking if a passive attacker is able to retrieve the payload plaintext only by compromising ${whom[0].toUpperCase()}${whom.substr(1)}'s static key either before or after the protocol session.`,
			`In this query, we test for <em>message secrecy</em> by checking if an active attacker is able to retrieve the payload plaintext only by compromising ${whom[0].toUpperCase()}${whom.substr(1)}'s static key either before or after the protocol session.`,
			`In this query, we test for <em>forward secrecy</em> by checking if a passive attacker is able to retrieve the payload plaintext only by compromising ${whom[0].toUpperCase()}${whom.substr(1)}'s static key before the protocol session, or after the protocol session along with ${who[0].toUpperCase()}${who.substr(1)}'s static public key (at any time.)`,
			`In this query, we test for <em>weak forward secrecy</em> by checking if an active attacker is able to retrieve the payload plaintext only by compromising ${whom[0].toUpperCase()}${whom.substr(1)}'s static key before the protocol session, or after the protocol session along with ${who[0].toUpperCase()}${who.substr(1)}'s static public key (at any time.)`,
			`In this query, we test for <em>strong forward secrecy</em> by checking if an active attacker is able to retrieve the payload plaintext only by compromising ${whom[0].toUpperCase()}${whom.substr(1)}'s static key before the protocol session.`,
		]
	};
	analysisTxt = [
		htmlTemplates.detailed.intro(pattern.name, abc, seq, dir),
	];
	analysisTxt = analysisTxt.concat(
		htmlTemplates.detailed.analysisTxt(pattern.name, abc, seq, dir, true, writeMessage, tokens)
	);
	analysisTxt = analysisTxt.concat(
		htmlTemplates.detailed.analysisTxt(pattern.name, abc, seq, dir, false, readMessage, tokens)
	);
	analysisTxt = analysisTxt.concat([
		`<h3>Queries and Results</h3>`,
		`Message <span class="mono">${abc.toUpperCase()}</span> is tested against four authenticity queries and five confidentiality queries.`
	]);
	for (let i = 1; i < 5; i++) {
		analysisTxt = analysisTxt.concat([
			`<h4>Authenticity Grade ${i}: ${(well(rawResultsActive[(message * 9) + i]))? '<span class="passed">Passed</span>' : '<span class="failed">Failed</span>'}</h4>`,
			`<p class="proverif"><br />${rawResultsActive[(message * 9) + i]}</p>`,
			`<p>${queryExplanations.authenticity[i]}</p>`
		]);
	}
	for (let i = 1; i < 6; i++) {
		let rawResults = ((i === 1) || (i === 3))? rawResultsPassive : rawResultsActive;
		let x = (i === 2)? 1 : (i === 3)? 2 : (i === 4)? 2 : (i === 5)? 3 : i
		analysisTxt = analysisTxt.concat([
			`<h4>Confidentiality Grade ${i}: ${(well(rawResults[((message * 9) + 5) + x]))? '<span class="passed">Passed</span>' : '<span class="failed">Failed</span>'}</h4>`,
			`<p class="proverif"><br />${rawResults[((message * 9) + 5) + x]}</p>`,
			`<p>${queryExplanations.confidentiality[i]}</p>`
		]);
	}
	return {
		arrowSvg: arrowSvg.join('\n'),
		analysisTxt: analysisTxt.join('\n'),
		title: `${pattern.name} - Message ${abc.toUpperCase()}`
	}
}

if (typeof(module) !== 'undefined') {
	// Node
	module.exports = {
		read: read,
		render: render,
		renderDetailed: renderDetailed
	};
} else {
	// Web
	NOISEREADER.read = read;
	NOISEREADER.render = render;
	NOISEREADER.renderDetailed = renderDetailed;
}

})();
