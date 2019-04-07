#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_kpsk0::{
	noisesession::NoiseSession,
	types::{Keypair, Message, MessageBuffer, PrivateKey, Psk, PublicKey},
};

#[test]
fn noiseexplorer_test_kpsk0() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let initStaticA: PrivateKey = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
	let respStatic_private: PrivateKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	let respStatic_public: PublicKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893").generate_public_key();
	let initStaticB: Keypair = Keypair::from_private_key(PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let pskA: Psk = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521");
	let pskB: Psk = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(initStaticA), respStatic_public, pskA);
	let mut responderSession: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(respStatic_private), PublicKey::from_str("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a"), pskB);
	initiatorSession.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	
	let mut messageA: MessageBuffer = initiatorSession.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79443b0588c609a0bd9a0fb1d3d84bc37d74f73c8129a00a76a49227b64fdac65b59");
	let mut messageB: MessageBuffer = responderSession.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("1696d649da9b1097e75bdba3769aa2861bad1de0ed782b7be6dd2b0ef56960");
	let mut messageC: MessageBuffer = initiatorSession.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("e3a19dbc2d8e912e4e79ebbf4df96e06b6a98de3ef59abbf3be526");
	let mut messageD: MessageBuffer = responderSession.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("e7d5f5db72092c35b70848efb126fb4a5910fc97b63e5e3eb7b2b6");
	let mut messageE: MessageBuffer = initiatorSession.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("32247d5e7da91884952be4b0623b6390fb4ff40175fa84df79387d840cf16a72e8");
	let mut messageF: MessageBuffer = responderSession.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("f06db65fb64b63764f82cbb628205620b55bc3900c7fbeaeb4c649e389d1c5a40b17455d1e");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for Kpsk0_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
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
