#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_x1k::{
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_x1k() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let init_static_a: PrivateKey = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
	let resp_static_private: PrivateKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	let resp_static_public: PublicKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893").generate_public_key();
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(init_static_a), resp_static_public);
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(resp_static_private), PublicKey::empty());
	initiator_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	responder_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")));
	let mut messageA: Vec<u8> = initiator_session.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944a175ecb6df0c9d1986db9543b96d60c240c19f9a373a8aa5451ca32e4a5608f8");
	let mut messageB: Vec<u8> = responder_session.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843c3e3deddc0219e7777000606fee22f8151e10720c99656f7e27c114704b278");
	let mut messageC: Vec<u8> = initiator_session.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("54434d5b1ef60a94688c489e676732cc2ce28b213d577cc6bc7c31dfebce15ccc24321adbf4cf969082fc0610273a418b59c6372be1942810317efb69b92ae9b2281fd64c704f6627ac680");
	let mut messageD: Vec<u8> = responder_session.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("e0ba8f7528de232c25cefab7e73b563889c58ecd8a7dea244ba693");
	let mut messageE: Vec<u8> = initiator_session.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("c443ad38b6772a329e78177bf7771cce331fda94880fc7545b928c82547871de02");
	let mut messageF: Vec<u8> = responder_session.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("62ecce974d09a08aa4c86cbc46ba96b34aeff12bdd70605d2449521b2ca3e11156cd8b3e0c");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for X1K_25519_ChaChaPoly_BLAKE2s."
	);
	assert!(tA.as_bytes() == &messageA,
		"\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tA.as_bytes(),
		&messageA
	);
	assert!(tB.as_bytes() == &messageB,
		"\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tB.as_bytes(),
		&messageB
	);
	assert!(tC.as_bytes() == &messageC,
		"\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tC.as_bytes(),
		&messageC
	);
	assert!(tD.as_bytes() == &messageD,
		"\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tD.as_bytes(),
		&messageD
	);
	assert!(tE.as_bytes() == &messageE,
		"\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tE.as_bytes(),
		&messageE
	);
	assert!(tF.as_bytes() == &messageF,
		"\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n",
		tF.as_bytes(),
		&messageF
	);
}
