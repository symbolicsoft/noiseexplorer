#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_i1x::{
	noisesession::NoiseSession,
	types::{Keypair, Message, MessageBuffer, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_i1x() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let init_static_a: PrivateKey = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
	let resp_static_private: PrivateKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(init_static_a), PublicKey::empty());
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(resp_static_private), PublicKey::empty());
	initiator_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	responder_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")));
	let mut messageA: MessageBuffer = initiator_session.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79446bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a4c756477696720766f6e204d69736573");
	let mut messageB: MessageBuffer = responder_session.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843fd2aa10551c5cc272741246f08d97aee64d9f253997dceb07cf208d11aecf846439c9465908576ea7e09e94e1c808c80bf7ad4614af5b338b2eb38f5d4723cf955dabaf932c9519bee1a46a4254a01");
	let mut messageC: MessageBuffer = initiator_session.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("1c9a70e3e02fd0165682fa3ca53e6af2b5fa9d56545c082e751c2d");
	let mut messageD: MessageBuffer = responder_session.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("1a72f460c7ef6f2716d21c8692c060ac24bec8773cff31863ff8d0");
	let mut messageE: MessageBuffer = initiator_session.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("ba3bc5ba75b5a4164856d8e728f978e692fff17b497abfbb778ff21cf8531088c7");
	let mut messageF: MessageBuffer = responder_session.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("5d19abfa0aea136ddf6964de30cd4dcda251be3ecee0ba31b44a6f7105b553a1581c212c46");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for I1X_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ns);
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
	cB.append(&mut Vec::from(&messageB.ne[..]));
	cB.append(&mut messageB.ns);
	cB.append(&mut messageB.ciphertext);
	let mut cC: Vec<u8> = Vec::new();
	cC.append(&mut messageC.ciphertext);
	let mut cD: Vec<u8> = Vec::new();
	cD.append(&mut messageD.ciphertext);
	let mut cE: Vec<u8> = Vec::new();
	cE.append(&mut messageE.ciphertext);
	let mut cF: Vec<u8> = Vec::new();
	cF.append(&mut messageF.ciphertext);
	assert!(tA.as_bytes() == &cA,
		"\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tA.as_bytes(),
		&cB
	);
	assert!(tB.as_bytes() == &cB,
		"\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tB.as_bytes(),
		&cB
	);
	assert!(tC.as_bytes() == &cC,
		"\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tC.as_bytes(),
		&cB
	);
	assert!(tD.as_bytes() == &cD,
		"\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tD.as_bytes(),
		&cB
	);
	assert!(tE.as_bytes() == &cE,
		"\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tE.as_bytes(),
		&cB
	);
	assert!(tF.as_bytes() == &cF,
		"\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tF.as_bytes(),
		&cB
	);
}
