#![allow(non_snake_case, non_upper_case_globals)]

use Npsk0;

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
	let initStatic: Npsk0::Keypair = Npsk0::Keypair::new_k(Npsk0::decode_str_32("Npsk0::EMPTY_KEY"));
	let respStatic: Npsk0::Keypair = Npsk0::Keypair::new_k(Npsk0::decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let temp_psk1: [u8; 32] =
	Npsk0::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let temp_psk2: [u8; 32] =
	Npsk0::decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let mut initiatorSession: Npsk0::NoiseSession =
	Npsk0::NoiseSession::InitSession(true, &prologue, initStatic, respStatic.pk.0, temp_psk1);
	let mut responderSession: Npsk0::NoiseSession =
	Npsk0::NoiseSession::InitSession(false, &prologue, respStatic, temp_psk2);
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: Npsk0::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944425cfde31517d0b610bab9bbd6e699b966415e2ce1454c0d5357dd445756df1f");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: Npsk0::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("06aaf2d9845c8324f528f20bd1c8f8e11f88b55bc7681798e11d3f745c4264");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: Npsk0::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("a1ce8e06add10426bc54463a1e7dc3d9f9526f7b44225cfa8eda3a");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: Npsk0::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("8d07ff4b04a1beba3ac8cf27a3fd5cebdc462383862bc71cb727da");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: Npsk0::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("9ee57cd3df98a99d460c8948c8fad51636a1f6a548d1b0bf5068d3562afc1461f4");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: Npsk0::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("3474938c4fac7a52c90be1e0a7c36c48d03a367e292e44a335e7f236eb5f385ec582737be8");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for Npsk0_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for Npsk0_25519_ChaChaPoly_BLAKE2s.");
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