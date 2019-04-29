#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_n::{
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_n() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let init_static_a: PrivateKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001");
	let resp_static_private: PrivateKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	let resp_static_public: PublicKey = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893").generate_public_key();
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(init_static_a), resp_static_public);
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(resp_static_private), PublicKey::empty());
	initiator_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	
	let mut messageA: Vec<u8> = initiator_session.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79441b168ed8bbe8220b52bbbde6593d109d78c299b567f6e69276efcf2659c39073");
	let mut messageB: Vec<u8> = responder_session.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("a7b5d1962001e9c4d965ea5f133941e9e6989094bcde637a582c34b954f34a");
	let mut messageC: Vec<u8> = initiator_session.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("16ff2557d5d671abe58c88d2a31b58e3a494ab3a6498124be0ea3f");
	let mut messageD: Vec<u8> = responder_session.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("1a6e85b0ef71c38db2c2bf3ebef1d41dc93e26bea6899187d5633d");
	let mut messageE: Vec<u8> = initiator_session.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("00ad2b7d0a03a748d0aefd3accee7bbbcc0bb0ed64d685b2ee8af78997a0245e3f");
	let mut messageF: Vec<u8> = responder_session.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("5631105c749b9550b27d7926dec0c5b83d4bf207688deccd51b50dd7fc9d5e337bba9c3177");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for N_25519_ChaChaPoly_BLAKE2s."
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
