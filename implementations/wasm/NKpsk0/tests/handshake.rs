#![allow(non_snake_case, non_upper_case_globals, unused_assignments, unused_imports)]
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use noiseexplorer_nkpsk0_wasm::{
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
fn noiseexplorer_test_nkpsk0() {

	let mut prologue: Vec<u8> = Vec::new();
	let mut messageA: Vec<u8> = Vec::new();	
	let mut messageB: Vec<u8> = Vec::new();
	let mut messageC: Vec<u8> = Vec::new();
	let mut messageD: Vec<u8> = Vec::new();	
	let mut messageE: Vec<u8> = Vec::new();
	let mut messageF: Vec<u8> = Vec::new();

	prologue = decode_str("4a6f686e2047616c74");
	let initiator_static_private = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
	let responder_static_private = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893").unwrap();
	let responder_static_public = responder_static_private.generate_public_key().unwrap();
	let initiator_static_kp = Keypair::from_private_key(initiator_static_private).unwrap();
	let responder_static_kp = Keypair::from_private_key(responder_static_private).unwrap();
	let psk = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521").unwrap();
	
	let mut initiator_session: NoiseSession = NoiseSession::init_session(true, &prologue[..], initiator_static_kp, Some(responder_static_public), psk.clone());
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, &prologue[..], responder_static_kp, None, psk);
	let initiator_ephemeral_private = PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a").unwrap();
	let initiator_ephemeral_kp = Keypair::from_private_key(initiator_ephemeral_private).unwrap();
	initiator_session.set_ephemeral_keypair(initiator_ephemeral_kp);
	let responder_ephemeral_private = PrivateKey::from_str("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b").unwrap();
	let responder_ephemeral_kp = Keypair::from_private_key(responder_ephemeral_private).unwrap();
	responder_session.set_ephemeral_keypair(responder_ephemeral_kp);
	messageA.extend_from_slice(&[0u8; DHLEN][..]);
	messageA.append(&mut decode_str("4c756477696720766f6e204d69736573"));
	messageA.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794427635ede06947b2d3acd77a36788aaaf17e9f5a8ac252e560fb421ba161a2cf8");
	// messageA length is 48 + payload length,
	// payload starts at index 32
	initiator_session.send_message(&mut messageA[..]).unwrap();
	responder_session.recv_message(&mut messageA.clone()[..]).unwrap();
	messageB.extend_from_slice(&[0u8; DHLEN][..]);
	messageB.append(&mut decode_str("4d757272617920526f746862617264"));
	messageB.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d682eb9cf4fee6816c8c8cfd34c15774321e234e3a426d7cfd3f13e5e84d04");
	// messageB length is 48 + payload length,
	// payload starts at index 32
	responder_session.send_message(&mut messageB[..]).unwrap();
	initiator_session.recv_message(&mut messageB.clone()[..]).unwrap();
	messageC.append(&mut decode_str("462e20412e20486179656b"));
	messageC.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tC: Vec<u8> = decode_str("b6645684db57679aa08f0b3352d58f32ec7f1e1a02083d5bd54277");
	// messageC length is 16 + payload length,
	// payload starts at index 0
	initiator_session.send_message(&mut messageC[..]).unwrap();
	responder_session.recv_message(&mut messageC.clone()[..]).unwrap();
	messageD.append(&mut decode_str("4361726c204d656e676572"));
	messageD.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tD: Vec<u8> = decode_str("473a9a4109eba0939e934640d318984df8d0900aa922f0195a09ad");
	// messageD length is 16 + payload length,
	// payload starts at index 0
	responder_session.send_message(&mut messageD[..]).unwrap();
	initiator_session.recv_message(&mut messageD.clone()[..]).unwrap();
	messageE.append(&mut decode_str("4a65616e2d426170746973746520536179"));
	messageE.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tE: Vec<u8> = decode_str("c8c44a16fff728f83e61272382149feadd3eb0ee1bab6313f84c72fe1581225236");
	// messageE length is 16 + payload length,
	// payload starts at index 0
	initiator_session.send_message(&mut messageE[..]).unwrap();
	responder_session.recv_message(&mut messageE.clone()[..]).unwrap();
	messageF.append(&mut decode_str("457567656e2042f6686d20766f6e2042617765726b"));
	messageF.extend_from_slice(&[0u8; MAC_LENGTH][..]);
	let tF: Vec<u8> = decode_str("21354f87158ac5e357529e87e8c84cfcdb49c8a080550c8f908d05ef7ea82ca525e3d1398e");
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
