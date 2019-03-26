#![allow(non_snake_case, non_upper_case_globals)]

use X1X1;

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
	let initStatic: X1X1::Keypair = X1X1::Keypair::new_k(X1X1::decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: X1X1::Keypair = X1X1::Keypair::new_k(X1X1::decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let mut initiatorSession: X1X1::NoiseSession =
	X1X1::NoiseSession::InitSession(true, &prologue, initStatic);
	let mut responderSession: X1X1::NoiseSession =
	X1X1::NoiseSession::InitSession(false, &prologue, respStatic);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: X1X1::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: X1X1::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435d6cf9082524088d7215adc1500b2508aa2a39da2c1b3bcae3ff68589e4d3b9ed239546fee7f896b715b5ae638825683cd78d4e704392dc4ed1be5c2ae6bc00d44a485dbad0221ed339fd3528e5d57");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: X1X1::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("7a53650f3808ce5122a4960beae9d6a24c09bd5190d1b724becf25b170372cfa08894568c72132ee7bcb08fdd79b7ff1bec209ad0143251911893316cc4546c35195f33fb710ad765ecc5c");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: X1X1::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("10294767f231b3f6d407a20f3870079c4f8e432350760a0b5f8ff7");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: X1X1::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("db9ab12b97aa415672ffd410cd2b7a2c9592fafd65e78b2a66624cde05c78f76e3");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: X1X1::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("2eece2d0a634c0a010ead5f9a950b0b7b86031794e0778bb0b1fffbc27740a35337594ed57");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for X1X1_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for X1X1_25519_ChaChaPoly_BLAKE2s.");
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