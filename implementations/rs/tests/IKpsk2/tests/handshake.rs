#![allow(non_snake_case, non_upper_case_globals)]

use IKpsk2;

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
	let initStatic: IKpsk2::Keypair = IKpsk2::Keypair::new_k(IKpsk2::decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: IKpsk2::Keypair = IKpsk2::Keypair::new_k(IKpsk2::decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let temp_psk1: [u8; 32] =
	IKpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	IKpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: IKpsk2::NoiseSession =
	IKpsk2::NoiseSession::InitSession(true, &prologue, initStatic, respStatic.pk.0, temp_psk1);
	let mut responderSession: IKpsk2::NoiseSession =
	IKpsk2::NoiseSession::InitSession(false, &prologue, respStatic, IKpsk2::EMPTY_KEY, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: IKpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944001e21de9f98ddd8e2ad57527207feb56253c9c94a9e496782ecfcb2a75fbcaf1b52948cc48daefe660c62119ab5000980c84831215f2441eba616548e832985464cf17e51ee93109008399a21f7e13f");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: IKpsk2::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843cb765f2caef0751b8f007572dab0322217755c0632f365717edbf34d33e87a");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: IKpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("8153ca9833bc3c1b91a7e66e5f4d4f5b59bf9e64c2f20d15f0bba7");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: IKpsk2::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("07af0c9c86e1b4e80f36b04ff7688d51141af3debd0332f0a705ef");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: IKpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("6ab1467c0448cc78394494abaaf23afce0e234315d6e2624dcbfa8a21c1c4d073d");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: IKpsk2::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("dfc346c0d2296ae6cf1acf6f12b8456a1dba228cf8d8b774aacf1c47fc53aa80ebc7a4c292");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for IKpsk2_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for IKpsk2_25519_ChaChaPoly_BLAKE2s.");
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