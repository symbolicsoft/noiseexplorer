#![allow(non_snake_case, non_upper_case_globals)]

use NKpsk2;

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
	let initStatic: NKpsk2::Keypair = NKpsk2::Keypair::new_k(NKpsk2::decode_str_32("NKpsk2::EMPTY_KEY"));
	let respStatic: NKpsk2::Keypair = NKpsk2::Keypair::new_k(NKpsk2::decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let temp_psk1: [u8; 32] =
	NKpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let temp_psk2: [u8; 32] =
	NKpsk2::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let mut initiatorSession: NKpsk2::NoiseSession =
	NKpsk2::NoiseSession::InitSession(true, &prologue, initStatic, respStatic.pk.0, temp_psk1);
	let mut responderSession: NKpsk2::NoiseSession =
	NKpsk2::NoiseSession::InitSession(false, &prologue, respStatic, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: NKpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79449b81e7722cc191126a9d3892203ec4cd791774188424a23f684ff03c726273de");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: NKpsk2::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d06453b74535a533d3ccb782a50b4f48c80f82d3b6d1bf72692144691a634f");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: NKpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("a6f7f4f5af57e015ee7e1a4113e09f637b9ed27d24cda23ab29262");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: NKpsk2::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("847a9067b69a7c5455900d88f5ce079487866a505ad8844929ebcc");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: NKpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("200d2686b66fe57c3ca8f24c37c04c64e6cba6fe08bbd5301d6d4734c1caf5b634");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: NKpsk2::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("b78d4f43dbbc99b97a64865b55e1856f4c97e95638666437c805a3f331ad4b48c5c31e7623");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for NKpsk2_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for NKpsk2_25519_ChaChaPoly_BLAKE2s.");
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