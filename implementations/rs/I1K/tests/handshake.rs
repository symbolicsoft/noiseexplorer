#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_i1k;
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
fn noiseexplorer_test_i1k() {
    let prologue = decode_str("4a6f686e2047616c74");
	let initStaticA: noiseexplorer_i1k::Keypair = noiseexplorer_i1k::Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: noiseexplorer_i1k::Keypair = noiseexplorer_i1k::Keypair::new_k(decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let mut initiatorSession: noiseexplorer_i1k::NoiseSession =
	noiseexplorer_i1k::NoiseSession::InitSession(true, &prologue, initStaticA, respStatic.pk.0);
	let mut responderSession: noiseexplorer_i1k::NoiseSession =
	noiseexplorer_i1k::NoiseSession::InitSession(false, &prologue, respStatic, noiseexplorer_i1k::EMPTY_KEY);
	initiatorSession.set_ephemeral_keypair(noiseexplorer_i1k::Keypair::new_k(decode_str_32(
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
	)));
	responderSession.set_ephemeral_keypair(noiseexplorer_i1k::Keypair::new_k(decode_str_32(
		"bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
	)));
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: noiseexplorer_i1k::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
		validA = true;
	}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944d203bb6ff07617535a8ae6edd3453496a5cdd89213abfc0d5548bf2c68caad6d9b6a063f53eb6e5736b93c69e3ac0679739ea6aca4d3dddad5d7c16a40978fbc0bd0cd4269b69233f8e054bc06bfd5b5");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: noiseexplorer_i1k::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
		validB = true;
	}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884350c8dd93488a51a98e5ab8f923f52558533a2e3e70ee83fcb968b28239446e");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: noiseexplorer_i1k::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
		validC = true;
	}
	let tC: Vec<u8> = decode_str("712ae62c9ad7d33bf98d5447e77ffeee4f3933a66c892b6a76d4d7");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: noiseexplorer_i1k::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
		validD = true;
	}
	let tD: Vec<u8> = decode_str("510867587e50c01439f6df4201db76355cb2ea0a46398f64f55a7a");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: noiseexplorer_i1k::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
		validE = true;
	}
	let tE: Vec<u8> = decode_str("e96974beb8b4959ef468fc4380539d132a88e775ff70cac15dbcfba6de80e71405");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: noiseexplorer_i1k::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
		validF = true;
	}
	let tF: Vec<u8> = decode_str("3e0da42459f5204cca1b89a7b616a849611a36882902c7de7a9a78ef01da8b644c80ed0f37");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for I1K_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ns);
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
