#![allow(non_snake_case, non_upper_case_globals)]

use NNpsk0;

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
	let initStatic: NNpsk0::Keypair = NNpsk0::Keypair::new_k(NNpsk0::decode_str_32("NNpsk0::EMPTY_KEY"));
	let respStatic: NNpsk0::Keypair = NNpsk0::Keypair::new_k(NNpsk0::decode_str_32("NNpsk0::EMPTY_KEY"));
	let temp_psk1: [u8; 32] =
	NNpsk0::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let temp_psk2: [u8; 32] =
	NNpsk0::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let mut initiatorSession: NNpsk0::NoiseSession =
	NNpsk0::NoiseSession::InitSession(true, &prologue, initStatic, temp_psk1);
	let mut responderSession: NNpsk0::NoiseSession =
	NNpsk0::NoiseSession::InitSession(false, &prologue, respStatic, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: NNpsk0::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944fda936bec35a8adfdff198386f7d5475880897edaaf7495314c99095a2e4d66a");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: NNpsk0::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088434cd2a371993ba41ea11448024fca32766b169183c9e691a7a433279da7e729");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: NNpsk0::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("bc44da303ae0beb08075fc4eb4e58235c67c2d1f53a4f2fff0bca7");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: NNpsk0::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("416d1af83e9fa6966ce4e871156b131aa9bd7e9a1d6f8794f4872a");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: NNpsk0::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("8a7d81b77bcc6c072f2b807da066efba6b5fab9edf71a7faceb2c8454b0cfef608");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: NNpsk0::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("1e2ee010f72894824a25a867664ff298f2548a145dc4e9d27b1cad83f32fa7c54d69dc3279");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for NNpsk0_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for NNpsk0_25519_ChaChaPoly_BLAKE2s.");
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