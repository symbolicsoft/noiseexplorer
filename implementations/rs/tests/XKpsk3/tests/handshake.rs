#![allow(non_snake_case, non_upper_case_globals)]

use XKpsk3;

fn decode_str(s: &str) -> Vec<u8> {
    if let Ok(x) = hex::decode(s) {
        x
    } else {
        panic!("{:X?}", hex::decode(s).err());
    }
}

#[test]
fn test() {
    	let prologue = decode_str("4a6f686e2047616c74");
	let initStatic: XKpsk3::Keypair = XKpsk3::Keypair::new_k(XKpsk3::decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: XKpsk3::Keypair = XKpsk3::Keypair::new_k(XKpsk3::decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let temp_psk1: [u8; 32] =
	XKpsk3::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	XKpsk3::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: XKpsk3::NoiseSession =
	XKpsk3::NoiseSession::InitSession(true, &prologue, initStatic, respStatic.pk.0, temp_psk1);
	let mut responderSession: XKpsk3::NoiseSession =
	XKpsk3::NoiseSession::InitSession(false, &prologue, respStatic, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: XKpsk3::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79446f78efab3dd17dddf573d7f399c41a491e3d4a8c643e419bdf51d1933b652b3a");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: XKpsk3::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884363bbc83fb0e2a44b36feb19c5ce545adb9cc59b96cc6b987ec62c8bb0db6e6");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: XKpsk3::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("285922ecd27adc8258a798d4f85ad5fcc86e7862210ea3dfa3cb23659a19630c6c2ff6890a0485e793a3620d87a652e527a394ac202551878895c866e86c74ab489720317c7dea72d8e652");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: XKpsk3::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("fc97959e232b766114c282617cda61c902ed282468130ec94e0efa");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: XKpsk3::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("78d7d2f41577b2ff7b1b2c62df539b3b0b45acd5ccb01d07e6e889c5f7a7682f06");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: XKpsk3::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("8040fee7bccafbb0ffbeffd38f1df4fdc0ac0c7ec182df49c81245d97838638df46d77158e");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for XKpsk3_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for XKpsk3_25519_ChaChaPoly_BLAKE2s.");
	}
	let mut cA: Vec<u8> = Vec::from(&messageA.ne[..]);
	cA.append(&mut messageA.ns);
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::from(&messageB.ne[..]);
	cB.append(&mut messageB.ns);
	cB.append(&mut messageB.ciphertext);
	let mut cC: Vec<u8> = messageC.ciphertext;
	let mut cD: Vec<u8> = messageD.ciphertext;
	let mut cE: Vec<u8> = messageE.ciphertext;
	let mut cF: Vec<u8> = messageF.ciphertext;
	if tA == cA {
		println!("Test A: PASS");
	} else {
		println!("Test A: FAIL");
		println!("Expected:	{:X?}", tA);
		println!("Actual:		{:X?}", cA);
	}
	if tB == cB {
		println!("Test B: PASS");
	} else {
		println!("Test B: FAIL");
		println!("Expected:	{:X?}", tB);
		println!("Actual:		{:X?}", cB);
	}
	if tC == cC {
		println!("Test C: PASS");
	} else {
		println!("Test C: FAIL");
		println!("Expected:	{:X?}", tC);
		println!("Actual:		{:X?}", cC);
	}
	if tD == cD {
		println!("Test D: PASS");
	} else {
		println!("Test D: FAIL");
		println!("Expected:	{:X?}", tD);
		println!("Actual:		{:X?}", cD);
	}
	if tE == cE {
		println!("Test E: PASS");
	} else {
		println!("Test E: FAIL");
		println!("Expected:	{:X?}", tE);
		println!("Actual:		{:X?}", cE);
	}
	if tF == cF {
		println!("Test F: PASS");
	} else {
		println!("Test F: FAIL");
		println!("Expected:	{:X?}", tF);
		println!("Actual:		{:X?}", cF);
	}
	assert_eq!(tA, cA);
	assert_eq!(tB, cB);
	assert_eq!(tC, cC);
	assert_eq!(tD, cD);
	assert_eq!(tE, cE);
	assert_eq!(tF, cF);
}