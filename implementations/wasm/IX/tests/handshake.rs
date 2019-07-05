#![allow(non_snake_case, non_upper_case_globals, unused_assignments, unused_imports)]
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use noiseexplorer_ix_wasm::{
	consts::{DHLEN, MAC_LENGTH},
	error::NoiseError,
	noisesession::NoiseSession,
	types::{Keypair, PrivateKey, PublicKey, Psk},
};
use std::str::FromStr;

fn decode_str(s: &str) -> Vec<u8> {
 	hex::decode(s).unwrap()
 }

#[wasm_bindgen_test]
fn noiseexplorer_test_ix() {

	let mut prologue: Vec<u8> = Vec::new();
	let mut messageA: Vec<u8> = Vec::new();	
	let mut messageB: Vec<u8> = Vec::new();
	let mut messageC: Vec<u8> = Vec::new();
	let mut messageD: Vec<u8> = Vec::new();	
	let mut messageE: Vec<u8> = Vec::new();
	let mut messageF: Vec<u8> = Vec::new();

	prologue = decode_str("4a6f686e2047616c74");
	let initiator_static_private = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1").unwrap();
	let responder_static_private = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893").unwrap();
	let initiator_static_kp = Keypair::from_private_key(initiator_static_private).unwrap();
	let responder_static_kp = Keypair::from_private_key(responder_static_private).unwrap();
	
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, &prologue[..], initiator_static_kp);
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, &prologue[..], responder_static_kp);
	let initiator_ephemeral_private = PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a").unwrap();
	let initiator_ephemeral_kp = Keypair::from_private_key(initiator_ephemeral_private).unwrap();
	initiator_session.set_ephemeral_keypair(initiator_ephemeral_kp);
	let responder_ephemeral_private = PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b").unwrap();
	let responder_ephemeral_kp = Keypair::from_private_key(responder_ephemeral_private).unwrap();
	responder_session.set_ephemeral_keypair(responder_ephemeral_kp);
	messageA.extend_from_slice(&[0u8; DHLEN][..]);
	messageA.extend_from_slice(&[0u8; DHLEN][..]);
	messageA.append(&mut decode_str("4c756477696720766f6e204d69736573"));
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79446bc3822a2aa7f4e6981d6538692b3cdf3e6df9eea6ed269eb41d93c22757b75a4c756477696720766f6e204d69736573");
	// messageA length is 64 + payload length,
	// payload starts at index 64
	initiator_session.send_message(&mut messageA[..]).unwrap();
	responder_session.recv_message(&mut messageA.clone()[..]).unwrap();
	messageB.extend_from_slice(&[0u8; DHLEN][..]);
	messageB.extend_from_slice(&[0u8; DHLEN+MAC_LENGTH][..]);
	messageB.append(&mut decode_str("4d757272617920526f746862617264"));
	messageB.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884398e7f90d906b0948dbc71ea7020ce711a6cfde5ed7ad1d43def67fb5be6190b5028fbb2556e9378b65b5e86195a7cd4cadddad64de91fbd1aaaae8621d31358a73dbfd6b68b96fb5bb8972bc28c2e2");
	// messageB length is 96 + payload length,
	// payload starts at index 80
	responder_session.send_message(&mut messageB[..]).unwrap();
	initiator_session.recv_message(&mut messageB.clone()[..]).unwrap();
	messageC.append(&mut decode_str("462e20412e20486179656b"));
	messageC.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tC: Vec<u8> = decode_str("62bc36955e7d6399c18531eb05fc8f4646da466a98a7e5cf1942e7");
	// messageC length is 16 + payload length,
	// payload starts at index 0
	initiator_session.send_message(&mut messageC[..]).unwrap();
	responder_session.recv_message(&mut messageC.clone()[..]).unwrap();
	messageD.append(&mut decode_str("4361726c204d656e676572"));
	messageD.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tD: Vec<u8> = decode_str("6be3ee3f7e5ccc4152754e4b22d87ee0045e6cd84654fd2ceb3720");
	// messageD length is 16 + payload length,
	// payload starts at index 0
	responder_session.send_message(&mut messageD[..]).unwrap();
	initiator_session.recv_message(&mut messageD.clone()[..]).unwrap();
	messageE.append(&mut decode_str("4a65616e2d426170746973746520536179"));
	messageE.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tE: Vec<u8> = decode_str("19b242089e28f5b8c2881f36dacb6953de1b576b722359a0ab8ac478c3c8fcacb1");
	// messageE length is 16 + payload length,
	// payload starts at index 0
	initiator_session.send_message(&mut messageE[..]).unwrap();
	responder_session.recv_message(&mut messageE.clone()[..]).unwrap();
	messageF.append(&mut decode_str("457567656e2042f6686d20766f6e2042617765726b"));
	messageF.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tF: Vec<u8> = decode_str("8db09f596ff2651900ff82316220328bb0ac49a520c58ff2504c67bb02c550d9546c483708");
	// messageF length is 16 + payload length,
	// payload starts at index 0
	responder_session.send_message(&mut messageF[..]).unwrap();
	initiator_session.recv_message(&mut messageF.clone()[..]).unwrap();
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
}
