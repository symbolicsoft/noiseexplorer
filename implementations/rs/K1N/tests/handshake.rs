#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_k1n::{
	noisesession::NoiseSession,
	types::{Keypair, Message, MessageBuffer, PrivateKey, Psk, PublicKey},
};

#[test]
fn noiseexplorer_test_k1n() {
    let prologueA: Message = Message::from_str("4a6f686e2047616c74");
	let prologueB: Message = Message::from_str("4a6f686e2047616c74");
	let initStaticA: PrivateKey = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
	let respStatic_private: PrivateKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001");
	let respStatic_public: PublicKey = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").generate_public_key();
	let initStaticB: Keypair = Keypair::from_private_key(PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let mut initiatorSession: NoiseSession = NoiseSession::init_session(true, prologueA, Keypair::from_private_key(initStaticA), PublicKey::empty());
	let mut responderSession: NoiseSession = NoiseSession::init_session(false, prologueB, Keypair::from_private_key(respStatic_private), PublicKey::from_str("6bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a"));
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
	let tB: Message = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884307b5e94aa0afb1c2fcbbf6ac664724b239fd021ae124adc88108d80ec0d666");
	let mut messageC: MessageBuffer = initiatorSession.send_message(Message::from_str("462e20412e20486179656b"));
	let mut validC: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageC) {
		validC = true;
	}
	let tC: Message = Message::from_str("82c0616f24490cd94f486c1619c85dc96abea27bf25182c9d1d6a0");
	let mut messageD: MessageBuffer = responderSession.send_message(Message::from_str("4361726c204d656e676572"));
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageD) {
		validD = true;
	}
	let tD: Message = Message::from_str("4fdb827ee0bd9b77aec3677f8b981c75aa98988cbea9e5a325efb1");
	let mut messageE: MessageBuffer = initiatorSession.send_message(Message::from_str("4a65616e2d426170746973746520536179"));
	let mut validE: bool = false;
	if let Some(_x) = responderSession.recv_message(&mut messageE) {
		validE = true;
	}
	let tE: Message = Message::from_str("e770f8f46305616e0c261db5bde1b543ec9865f63b49d566529c5f093277200a92");
	let mut messageF: MessageBuffer = responderSession.send_message(Message::from_str("457567656e2042f6686d20766f6e2042617765726b"));
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.recv_message(&mut messageF) {
		validF = true;
	}
	let tF: Message = Message::from_str("88c84d0f4a7a190a7fec9f8515915e7a516f8aea7b6c8d49c2a642363bb579c22e82b6b71f");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for K1N_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
	cB.append(&mut Vec::from(&messageB.ne[..]));
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
