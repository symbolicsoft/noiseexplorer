#![allow(non_snake_case, non_upper_case_globals)]

use INpsk1;

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
	let initStatic: INpsk1::Keypair = INpsk1::Keypair::new_k(INpsk1::decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: INpsk1::Keypair = INpsk1::Keypair::new_k(INpsk1::decode_str_32("INpsk1::EMPTY_KEY"));
	let temp_psk1: [u8; 32] =
	INpsk1::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	INpsk1::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: INpsk1::NoiseSession =
	INpsk1::NoiseSession::InitSession(true, &prologue, initStatic, INpsk1::EMPTY_KEY, temp_psk1);
	let mut responderSession: INpsk1::NoiseSession =
	INpsk1::NoiseSession::InitSession(false, &prologue, respStatic, INpsk1::EMPTY_KEY, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: INpsk1::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944b176e1321b6fad80cc0061e427c7f26f1ab6b27c1a19efffa2bb856394ed2076a6ece2790b022a8aad416d95a34e9e496e41c8f23860ff8370837b246baf6ee01aa19f4e7df52f2084f610c30ee69869");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: INpsk1::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884359f7be8d068d9fb4e2577e8c23de6f7e758d48d7a455ccb70546083277a438");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: INpsk1::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("7c2709807ef27264430900f89690ae9816886e24478f5d3cdd867b");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: INpsk1::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("498bcf0fe7fc095ed82f40c32505d4114d3aae5bcc8d2ae49b8928");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: INpsk1::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("10a7cb90fdfa4a98a016d22bc8cad2836582f24f79bf32ee8acbae3f7ab9a8c53b");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: INpsk1::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("77deacedc4e25dad434104a7aab852d5b9e043ef203873651ea052d8374eefa93726f462db");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for INpsk1_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for INpsk1_25519_ChaChaPoly_BLAKE2s.");
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