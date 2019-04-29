#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_nx1::{
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_nx1() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let init_static_a: PrivateKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001");
	let resp_static_private: PrivateKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(init_static_a), PublicKey::empty());
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(resp_static_private), PublicKey::empty());
	initiator_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	responder_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")));
	let mut messageA: Vec<u8> = initiator_session.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573");
	let mut messageB: Vec<u8> = responder_session.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088439b30cefd4ed5f364767278a44af908e027770a1bbb5cb73b4845623fde14f568c00acef543087cac6c296ac008b718035dcc25bdcbe85781484781f697bef836c7529d69c10129208d18141dfd84a8");
	let mut messageC: Vec<u8> = initiator_session.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("a123b0d1172ec45edda98b5e3728c9c08d3fc80bf90df75a07b185");
	let mut messageD: Vec<u8> = responder_session.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("0bd49626637293f0d0a610b56ba093c25e82c3d2c262020db10732");
	let mut messageE: Vec<u8> = initiator_session.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("8a7582a7b69081ddbae8e89ea5e2da4154c368875dbac46e729564349c3acf5526");
	let mut messageF: Vec<u8> = responder_session.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("82b62e297aae61ab5d6903ad401b85f4d75dd9b71503cd830b8c82607a4a1dc808c4eee32f");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for NX1_25519_ChaChaPoly_BLAKE2s."
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
