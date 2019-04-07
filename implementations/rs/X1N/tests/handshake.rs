#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_x1n::{
	noisesession::NoiseSession,
	types::{Keypair, Message, MessageBuffer, PrivateKey, Psk, PublicKey},
};

#[test]
fn noiseexplorer_test_x1n() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let initStaticA: PrivateKey = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
	let respStatic_private: PrivateKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001");
	let respStatic_public: PublicKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").generate_public_key();
	let mut initiatorSession: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(initStaticA), PublicKey::empty());
	let mut responderSession: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(respStatic_private), PublicKey::empty());
	initiatorSession.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	responderSession.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")));
	let mut messageA: MessageBuffer = initiatorSession.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573");
	let mut messageB: MessageBuffer = responderSession.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d2a6d85157ee61d979741bf7295b2536d3b380b95ae967795c40cc048f6486");
	let mut messageC: MessageBuffer = initiatorSession.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("ebfd2dff95b8d144f616212579ecf0faa109cc2de5af9e77d20bafaa1de70676c093cba24277162a3f6b6565a730604c75d3c2aae8f5e71564194e66f35cf4c2c86d7f66987f75ab0aa507");
	let mut messageD: MessageBuffer = responderSession.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("5dc0e26bf720c7ce31c16e09aed6ca7fa78a6f3db0f190cf7a5e8c");
	let mut messageE: MessageBuffer = initiatorSession.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("1d85ff0ab94a7831237b6e9eb11a4ddff3ad1eb0f438d73105a350a90a35210995");
	let mut messageF: MessageBuffer = responderSession.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("d2781f144c47a5f83735111d330cc81380af9b0989e9416b5a34759dc0e24c47c589cf4c14");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for X1N_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
	cB.append(&mut Vec::from(&messageB.ne[..]));
	cB.append(&mut messageB.ciphertext);
	let mut cC: Vec<u8> = Vec::new();
	cC.append(&mut messageC.ns);
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
