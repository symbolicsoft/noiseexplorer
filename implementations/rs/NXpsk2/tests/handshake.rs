#![allow(non_snake_case, non_upper_case_globals)]

use NXpsk2;

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
	let initStaticA: NXpsk2::Keypair = NXpsk2::Keypair::new_k(NXpsk2::EMPTY_KEY);
	let initStaticB: NXpsk2::Keypair = NXpsk2::Keypair::new_k(NXpsk2::EMPTY_KEY);
	let respStatic: NXpsk2::Keypair = NXpsk2::Keypair::new_k(NXpsk2::decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let temp_psk1: [u8; 32] =
	NXpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	NXpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: NXpsk2::NoiseSession =
	NXpsk2::NoiseSession::InitSession(true, &prologue, initStaticA, NXpsk2::EMPTY_KEY, temp_psk1);
	let mut responderSession: NXpsk2::NoiseSession =
	NXpsk2::NoiseSession::InitSession(false, &prologue, respStatic, NXpsk2::EMPTY_KEY, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: NXpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
		validA = true;
	}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794497bdcf5dc128b7bc5b8f2b6ac1a46dff9f9469337cfac0098f87b2a577cece84");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: NXpsk2::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
		validB = true;
	}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843c39479e89953f195c89ee9a53f2e291727e15ab09a61b1ca623ee98d3d2549bda7af1881b0ae7ba4bb6e8f71e119927c6c8510ae728cd8c258c6200b71c86e16f934ba80fe35e708f8a52a5e193346");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: NXpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
		validC = true;
	}
	let tC: Vec<u8> = decode_str("499085038a82c4bc9895c069b9a71ead87545a9184a395d74378e1");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: NXpsk2::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
		validD = true;
	}
	let tD: Vec<u8> = decode_str("966e81056dafc90a22e1b23039427325cab7791b92bed9a562808e");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: NXpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
		validE = true;
	}
	let tE: Vec<u8> = decode_str("f5731b781c54f95e5c75bbd6b9b88113de6097618936495b0ba90d545187a3512c");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: NXpsk2::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
		validF = true;
	}
	let tF: Vec<u8> = decode_str("1ad6f2ce261f2f6773363a6f3efc2105c98d960b910629da596e394b052389c66ae988bd84");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for NXpsk2_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for NXpsk2_25519_ChaChaPoly_BLAKE2s.");
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