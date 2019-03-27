#![allow(non_snake_case, non_upper_case_globals)]

use NNpsk2;

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
	let initStaticA: NNpsk2::Keypair = NNpsk2::Keypair::new_k(NNpsk2::EMPTY_KEY);
	let initStaticB: NNpsk2::Keypair = NNpsk2::Keypair::new_k(NNpsk2::EMPTY_KEY);
	let respStatic: NNpsk2::Keypair = NNpsk2::Keypair::new_k(NNpsk2::EMPTY_KEY);
	let temp_psk1: [u8; 32] =
	NNpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	NNpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: NNpsk2::NoiseSession =
	NNpsk2::NoiseSession::InitSession(true, &prologue, initStaticA, NNpsk2::EMPTY_KEY, temp_psk1);
	let mut responderSession: NNpsk2::NoiseSession =
	NNpsk2::NoiseSession::InitSession(false, &prologue, respStatic, NNpsk2::EMPTY_KEY, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: NNpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
		validA = true;
	}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79447dabf550042b63cd69e1826848d383fce196ed4a9d55205c3e555ef49aaa3239");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: NNpsk2::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
		validB = true;
	}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437ec230bbb3c3c83e65e2678f34d59bf01abb502670bb0e53b6bc8adb0646ea");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: NNpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
		validC = true;
	}
	let tC: Vec<u8> = decode_str("1767dbf2433c64ad3ba968745e0b84f6b560d2dc1083058cc8fac2");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: NNpsk2::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
		validD = true;
	}
	let tD: Vec<u8> = decode_str("99d59bf6f0c25b4ae6d683675edfe7eba6b3fdcef797833973805f");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: NNpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
		validE = true;
	}
	let tE: Vec<u8> = decode_str("b09f1a88b362d1f5873a843788dad3b62bb2d9e539857135c9c0e24c301de44b98");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: NNpsk2::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
		validF = true;
	}
	let tF: Vec<u8> = decode_str("642a09ab5ad552d34a819c5432ff09c0c4d616e78374bfd323b59482302b130b6413a2e5d4");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for NNpsk2_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for NNpsk2_25519_ChaChaPoly_BLAKE2s.");
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