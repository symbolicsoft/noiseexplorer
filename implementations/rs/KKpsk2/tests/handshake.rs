#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_kkpsk2;
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
fn noiseexplorer_test_kkpsk2() {
    let prologue = decode_str("4a6f686e2047616c74");
	let initStaticA: noiseexplorer_kkpsk2::Keypair = noiseexplorer_kkpsk2::Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: noiseexplorer_kkpsk2::Keypair = noiseexplorer_kkpsk2::Keypair::new_k(decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let initStaticB: noiseexplorer_kkpsk2::Keypair = noiseexplorer_kkpsk2::Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let temp_psk1: [u8; 32] =
	decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let temp_psk2: [u8; 32] =
	decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521");
	let mut initiatorSession: noiseexplorer_kkpsk2::NoiseSession =
	noiseexplorer_kkpsk2::NoiseSession::InitSession(true, &prologue, initStaticA, respStatic.pk.0, temp_psk1);
	let mut responderSession: noiseexplorer_kkpsk2::NoiseSession =
	noiseexplorer_kkpsk2::NoiseSession::InitSession(false, &prologue, respStatic, initStaticB.pk.0, temp_psk2);
	initiatorSession.set_ephemeral_keypair(noiseexplorer_kkpsk2::Keypair::new_k(decode_str_32(
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
	)));
	responderSession.set_ephemeral_keypair(noiseexplorer_kkpsk2::Keypair::new_k(decode_str_32(
		"bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
	)));
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: noiseexplorer_kkpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
		validA = true;
	}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794449af0184c65dee97ea7a62c425167842186a38ba37a2240d792e0adfa651f02d");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: noiseexplorer_kkpsk2::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
		validB = true;
	}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ae4b9f90df714c75293849a0c2f7ba8080ae48c13cbf90e2c69fd23df280eb");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: noiseexplorer_kkpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
		validC = true;
	}
	let tC: Vec<u8> = decode_str("aaa6fbdefc0c1c2c65cb912552fe0f9647b12fce48f3d2a66d9fac");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: noiseexplorer_kkpsk2::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
		validD = true;
	}
	let tD: Vec<u8> = decode_str("b872a76b5197ced1b61f9043789be7b32281aa8670d9fa166a6e95");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: noiseexplorer_kkpsk2::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
		validE = true;
	}
	let tE: Vec<u8> = decode_str("9e39948aa43a63d23e775e2bf15b4e80fad721d09e8060c242eea9970cfecf4a1f");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: noiseexplorer_kkpsk2::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
		validF = true;
	}
	let tF: Vec<u8> = decode_str("3ab72ae66cd9d291ae0ace1a71047dd55c3f36d662c250c711a06de3c6e44310c2913728dd");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for KKpsk2_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
	cB.append(&mut Vec::from(&messageB.ne[..]));
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
