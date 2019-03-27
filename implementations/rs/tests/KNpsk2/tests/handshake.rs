#![allow(non_snake_case, non_upper_case_globals)]

use KNpsk2;

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
	let initStatic: KNpsk2::Keypair = KNpsk2::Keypair::new_k(KNpsk2::decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: KNpsk2::Keypair = KNpsk2::Keypair::new_k(KNpsk2::decode_str_32("KNpsk2::EMPTY_KEY"));
	let temp_psk1: [u8; 32] =
	KNpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	KNpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: KNpsk2::NoiseSession =
	KNpsk2::NoiseSession::InitSession(true, &prologue, initStatic, KNpsk2::EMPTY_KEY, temp_psk1);
	let mut responderSession: KNpsk2::NoiseSession =
	KNpsk2::NoiseSession::InitSession(false, &prologue, respStatic, initStatic.pk.0, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: KNpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944d8b18198501b129b05163c3b4ea9e59ef49238f28730d4398699fba2e78391c0");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: KNpsk2::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884374519fa9659111620fe0c21e8b62e878e1819f85da30424693628ca755fc24");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: KNpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("9295326f750e4cc6238088c6127bae20cbe8c0a278ad9c970ce8f2");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: KNpsk2::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("be3e544073b0db44e045633b1f9b2ec43764095c84f96bdfef7f4c");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: KNpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("f42c2439ddfe2f82efa4eabe67f26b971ddfedc499554c5ec1c1ac888b184a0c7f");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: KNpsk2::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("b9533b3fcfb737497cab64a70ab09dc5de68d022ace8c833b3aa8fa51da7a2ceddd86fd5cd");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for KNpsk2_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for KNpsk2_25519_ChaChaPoly_BLAKE2s.");
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