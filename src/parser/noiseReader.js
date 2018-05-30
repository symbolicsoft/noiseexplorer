const NOISEREADER = {
	read: () => {},
	render: () => {}
};

(() => {

const util = {
	abc: ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']
};

const readRules = {
	rawResult: /^RESULT.+(is false|is true|cannot be proved)\.$/,
	authenticity: {
		sanity: /^RESULT event\(RecvMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) ==> event\(SendMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\)/,
		one: /^RESULT event\(RecvMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) ==> event\(SendMsg\((alice|bob),c_\d{1,8},stage_\w,m,true\)\) \|\| event\(LeakS\(phase0,(alice|bob)\)\) \|\| event\(LeakS\(phase0,(alice|bob)\)\)/,
		two: /^RESULT event\(RecvMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) ==> event\(SendMsg\((alice|bob),c_\d{1,8},stage_\w\(\w{1,8}\),m,true\)\) \|\| event\(LeakS\(phase0,(alice|bob)\)\)/,
		three: /^RESULT event\(RecvMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) ==> event\(SendMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) \|\| event\(LeakS\(phase0,(alice|bob)\)\) \|\| event\(LeakS\(phase0,(alice|bob)\)\)/,
		four: /^RESULT event\(RecvMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) ==> event\(SendMsg\((alice|bob),(alice|bob),stage_\w\(\w{1,8}\),m,true\)\) \|\| event\(LeakS\(phase0,(alice|bob)\)\)/
	},
	confidentiality: {
		sanity: /^RESULT not attacker_p1\(msg_\w\((alice|bob),(alice|bob)\)\)/,
		two: /^RESULT attacker_p1\(msg_\w\((alice|bob),(alice|bob)\)\) ==> event\(LeakS\(phase0,(alice|bob)\)\) \|\| event\(LeakS\(phase1,(alice|bob)\)\)/,
		thour: /^RESULT attacker_p1\(msg_\w\((alice|bob),(alice|bob)\)\) ==> event\(LeakS\(phase0,(alice|bob)\)\) \|\| \(event\(LeakS\(phase1,(alice|bob)\)\) && event\(LeakS\(p,(alice|bob)\)\)\)/,
		five: /^RESULT attacker_p1\(msg_\w\((alice|bob),(alice|bob)\)\) ==> event\(LeakS\(phase0,(alice|bob)\)\)/
	},
	sanity: /^RESULT not event\(RecvEnd\(true\)\)/
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
			2: `benefits from <em>receiver authentication</em> and is <em>resistant to Key Compromise Impersonation</em>. Assuming the corresponding private keys are secure, this authentication cannot be forged. However, if the ${who} carries out a separate session with a separate, compromised ${whom}, this other session can be used to forge the authenticity of this message with this session's ${whom}`,
			3: `benefits from <em>receiver authentication</em> but is <em>vulnerable to Key Compromise Impersonation</em>. If the ${whom}'s long-term private key has been compromised, this authentication can be forged`,
			4: `benefits from <em>sender/receiver authentication</em> and is <em>resistant to Key Compromise Impersonation</em>. Assuming the corresponding private keys are secure, this authentication cannot be forged`
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
			`\n\t\t\t<h3>Message ${abc.toUpperCase()}</h3>`,
			`<p>Message ${abc.toUpperCase()}, sent by the ${who}, ${authPhrases[authenticity]}. ${confPhrases[confidentiality]}. ${sanPhrases[sanity]} <span class="resultNums">${authenticity},${confidentiality}</span></p>`
		].join('\n\t\t\t');
		return phrase;
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
		let stage = new RegExp(`stage_${abc}`);
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
	if (rawResult.match(/stage_\w/)) {
		return rawResult.match(/stage_\w/)[0][6];
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
	rawResults.forEach((rawResult) => {
		let isTrue = well(rawResult);
		if (readRules.sanity.test(rawResult)) {
			readResults.sanity = !isTrue;
		} else {
			let abc = getMsgAbc(rawResult);
			if (readRules.confidentiality.thour.test(rawResult)) {
				readResults[abc].confidentiality.thour = isTrue;
			} else if (readRules.confidentiality.two.test(rawResult)) {
				readResults[abc].confidentiality.two = isTrue;
			} else if (readRules.confidentiality.five.test(rawResult)) {
				readResults[abc].confidentiality.five = isTrue;
			} else if (readRules.confidentiality.sanity.test(rawResult)) {
				readResults[abc].confidentiality.sanity = !isTrue;
			} else if (readRules.authenticity.one.test(rawResult)) {
				readResults[abc].authenticity.one = isTrue;
			} else if (readRules.authenticity.three.test(rawResult)) {
				readResults[abc].authenticity.three = isTrue;
			} else if (readRules.authenticity.two.test(rawResult)) {
				readResults[abc].authenticity.two = isTrue;
			} else if (readRules.authenticity.four.test(rawResult)) {
				readResults[abc].authenticity.four = isTrue;
			} else if (readRules.authenticity.sanity.test(rawResult)) {
				readResults[abc].authenticity.sanity = !isTrue;
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
	let arrowSvg = ``;
	let analysisTxt = ``;
	let rawResultsDiv = ``;
	let offset = 30;
	let offsetIncrement = 135;
	if (pattern.preMessages.length) {
		pattern.preMessages.forEach((preMessage) => {
			arrowSvg += htmlTemplates[`${preMessage.dir}PreMessage`](
				offset, preMessage.tokens
			);
			offset = offset + offsetIncrement;
			analysisTxt += htmlTemplates.analysisPreMessage(
				preMessage.dir, preMessage.tokens
			);
		});
		arrowSvg += htmlTemplates.ellipsis(offset);
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
				/* readResultsActive.sanity */ true
			);
			analysisTxt += htmlTemplates.analysisMessage(
				abc, message.dir, message.tokens,
				authenticity, confidentiality, sanity
			);
		}
		arrowSvg += htmlTemplates[`${message.dir}Message`](
			offset, util.abc[i],
			message.tokens.join(', '),
			authenticity,
			confidentiality
		);
		offset = offset + offsetIncrement;
	});
	if (
		rawResultsActive.length &&
		rawResultsPassive.length
	) {
		rawResultsDiv = [
			`<h2>raw results &mdash; active attacker</h2>`,
			`${rawResultsActive.join('<br />').toLowerCase()}`,
			`<h2>raw results &mdash; passive attacker</h2>`,
			`${rawResultsPassive.join('<br />').toLowerCase()}`,
			`<br /><br />`
		].join('\n');
	}
	return {arrowSvg, analysisTxt, rawResultsDiv, offset};
};

if (typeof(module) !== 'undefined') {
	// Node
	module.exports = {
		read: read,
		render: render
	};
} else {
	// Web
	NOISEREADER.read = read;
	NOISEREADER.render = render;
}

})();