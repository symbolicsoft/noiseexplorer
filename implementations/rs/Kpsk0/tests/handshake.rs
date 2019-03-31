#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_kpsk0;
use hex;

fn decode_str(s: &str) -> Vec<u8> {
    if let Ok(x) = hex::decode(s) {
        x
    } else {
        panic!("{:X?}", hex::decode(s).err());
    }
}

fn decode_str_32(s: &str) -> [u8; 32] {
	if let Ok(x) = hex::decode(s) {
		if x.len() == 32 {
			let mut temp: [u8; 32] = [0u8; 32];
			temp.copy_from_slice(&x[..]);
			temp
		} else {
			panic!("Invalid input length; decode_32");
		}
	} else {
		panic!("Invalid input length; decode_32");
	}
}

#[test]
fn noiseexplorer_test_kpsk0() {
    let prologue = decode_str("4a6f686e2047616c74");
	let initStaticA: noiseexplorer_kpsk0::Keypair = noiseexplorer_kpsk0::Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: noiseexplorer_kpsk0::Keypair = noiseexplorer_kpsk0::Keypair::new_k(decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let initStaticB: noiseexplorer_kpsk0::Keypair = noiseexplorer_kpsk0::Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let temp_psk1: [u8; 32] =
	decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: noiseexplorer_kpsk0::NoiseSession =
	noiseexplorer_kpsk0::NoiseSession::InitSession(true, &prologue, initStaticA, respStatic.pk.0, temp_psk1);
	let mut responderSession: noiseexplorer_kpsk0::NoiseSession =
	noiseexplorer_kpsk0::NoiseSession::InitSession(false, &prologue, respStatic, initStaticB.pk.0, temp_psk2);
	initiatorSession.set_ephemeral_keypair(noiseexplorer_kpsk0::Keypair::new_k(decode_str_32(
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
	)));
	
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: noiseexplorer_kpsk0::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
		validA = true;
	}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79443b0588c609a0bd9a0fb1d3d84bc37d74f73c8129a00a76a49227b64fdac65b59");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: noiseexplorer_kpsk0::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
		validB = true;
	}
	let tB: Vec<u8> = decode_str("1696d649da9b1097e75bdba3769aa2861bad1de0ed782b7be6dd2b0ef56960");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: noiseexplorer_kpsk0::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
		validC = true;
	}
	let tC: Vec<u8> = decode_str("e3a19dbc2d8e912e4e79ebbf4df96e06b6a98de3ef59abbf3be526");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: noiseexplorer_kpsk0::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
		validD = true;
	}
	let tD: Vec<u8> = decode_str("e7d5f5db72092c35b70848efb126fb4a5910fc97b63e5e3eb7b2b6");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: noiseexplorer_kpsk0::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
		validE = true;
	}
	let tE: Vec<u8> = decode_str("32247d5e7da91884952be4b0623b6390fb4ff40175fa84df79387d840cf16a72e8");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: noiseexplorer_kpsk0::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
		validF = true;
	}
	let tF: Vec<u8> = decode_str("f06db65fb64b63764f82cbb628205620b55bc3900c7fbeaeb4c649e389d1c5a40b17455d1e");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for Kpsk0_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
	cB.append(&mut messageB.ciphertext);
	let mut cC: Vec<u8> = Vec::new();
	cC.append(&mut messageC.ciphertext);
	let mut cD: Vec<u8> = Vec::new();
	cD.append(&mut messageD.ciphertext);
	let mut cE: Vec<u8> = Vec::new();
	cE.append(&mut messageE.ciphertext);
	let mut cF: Vec<u8> = Vec::new();
	cF.append(&mut messageF.ciphertext);
	assert!(tA == cA,"\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n", tA, cA);
	assert!(tB == cB,"\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n", tB, cB);
	assert!(tC == cC,"\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n", tC, cC);
	assert!(tD == cD,"\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n", tD, cD);
	assert!(tE == cE,"\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n", tE, cE);
	assert!(tF == cF,"\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}\n\n\n", tF, cF);
}
