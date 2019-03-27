#![allow(non_snake_case, non_upper_case_globals)]

use NN;

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
	let initStatic: NN::Keypair = NN::Keypair::new_k(NN::decode_str_32("NN::EMPTY_KEY"));
	let respStatic: NN::Keypair = NN::Keypair::new_k(NN::decode_str_32("NN::EMPTY_KEY"));
	let mut initiatorSession: NN::NoiseSession =
	NN::NoiseSession::InitSession(true, &prologue, initStatic, NN::EMPTY_KEY);
	let mut responderSession: NN::NoiseSession =
	NN::NoiseSession::InitSession(false, &prologue, respStatic, NN::EMPTY_KEY);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: NN::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: NN::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ff34a6759d06e7733c83aeb5556c15bc762b664b3ba0556b1e7eaea4168bb6");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: NN::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("79285da88da3535f52b07b70006c85706de7ddb1fd3dddac995b7e");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: NN::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("ffdad3a7f0db4c39077f223659c5c1d107666405566ecdf4ab53bf");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: NN::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("2b9801f5084b9a7e9df57382fb4af099a63cd8ff97bc3284c4c5f28994be58ae46");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: NN::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("6c94a97c5de175c870fb9e8d5c50c59d20752b0695baf24e151011ee46a184a65b444e9d97");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for NN_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for NN_25519_ChaChaPoly_BLAKE2s.");
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