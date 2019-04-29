#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_inpsk1::{
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey, Psk},
};

#[test]
fn noiseexplorer_test_inpsk1() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let init_static_a: PrivateKey = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
	let resp_static_private: PrivateKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001");
	let pskA: Psk = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521");
	let pskB: Psk = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(init_static_a), PublicKey::empty(), pskA);
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(resp_static_private), PublicKey::empty(), pskB);
	initiator_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")));
	responder_session.set_ephemeral_keypair(Keypair::from_private_key(PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")));
	let mut messageA: Vec<u8> = initiator_session.send_message(Message::from_str("4c756477696720766f6e204d69736573"));
	let mut validA: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageA) {
		validA = true;
	}
	let tA: Message = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944b176e1321b6fad80cc0061e427c7f26f1ab6b27c1a19efffa2bb856394ed2076a6ece2790b022a8aad416d95a34e9e496e41c8f23860ff8370837b246baf6ee01aa19f4e7df52f2084f610c30ee69869");
	let mut messageB: Vec<u8> = responder_session.send_message(Message::from_str("4d757272617920526f746862617264"));
	let mut validB: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageB) {
		validB = true;
	}
	let tB: Message = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884359f7be8d068d9fb4e2577e8c23de6f7e758d48d7a455ccb70546083277a438");
	let mut messageC: Vec<u8> = initiator_session.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("7c2709807ef27264430900f89690ae9816886e24478f5d3cdd867b");
	let mut messageD: Vec<u8> = responder_session.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("498bcf0fe7fc095ed82f40c32505d4114d3aae5bcc8d2ae49b8928");
	let mut messageE: Vec<u8> = initiator_session.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responder_session.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("10a7cb90fdfa4a98a016d22bc8cad2836582f24f79bf32ee8acbae3f7ab9a8c53b");
	let mut messageF: Vec<u8> = responder_session.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiator_session.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("77deacedc4e25dad434104a7aab852d5b9e043ef203873651ea052d8374eefa93726f462db");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for INpsk1_25519_ChaChaPoly_BLAKE2s."
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
