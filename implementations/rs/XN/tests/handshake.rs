#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_xn;
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
fn noiseexplorer_test_xn() {
    let prologue = decode_str("4a6f686e2047616c74");
	let initStaticA: noiseexplorer_xn::Keypair = noiseexplorer_xn::Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: noiseexplorer_xn::Keypair = noiseexplorer_xn::Keypair::new_k(noiseexplorer_xn::EMPTY_KEY);
	let mut initiatorSession: noiseexplorer_xn::NoiseSession =
	noiseexplorer_xn::NoiseSession::InitSession(true, &prologue, initStaticA, noiseexplorer_xn::EMPTY_KEY);
	let mut responderSession: noiseexplorer_xn::NoiseSession =
	noiseexplorer_xn::NoiseSession::InitSession(false, &prologue, respStatic, noiseexplorer_xn::EMPTY_KEY);
	initiatorSession.set_ephemeral_keypair(noiseexplorer_xn::Keypair::new_k(decode_str_32(
		"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
	)));
	responderSession.set_ephemeral_keypair(noiseexplorer_xn::Keypair::new_k(decode_str_32(
		"bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
	)));
	let payloadA = decode_str("4c756477696720766f6e204d69736573");
	let mut messageA: noiseexplorer_xn::MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageA) {
		validA = true;
	}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573");
	let payloadB = decode_str("4d757272617920526f746862617264");
	let mut messageB: noiseexplorer_xn::MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageB) {
		validB = true;
	}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843dc00ccf629492772082cf28c171db3ec2dbc406aa59cca67a7a174501ccdca");
	let payloadC = decode_str("462e20412e20486179656b");
	let mut messageC: noiseexplorer_xn::MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageC) {
		validC = true;
	}
	let tC: Vec<u8> = decode_str("0bb0ae2b390d37a5aea005ffac23173e212f2234bbb4da3013ba0ad8ad8ec2f8a1e941c22a19c6904bee596238ecc6f5fadbb2881461b78ad9230a7838743e6160919412061d383a547510");
	let payloadD = decode_str("4361726c204d656e676572");
	let mut messageD: noiseexplorer_xn::MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageD) {
		validD = true;
	}
	let tD: Vec<u8> = decode_str("a378ce38a1df8f3e80a85c5a8709f3a17581ff8a2888e2a8446f65");
	let payloadE = decode_str("4a65616e2d426170746973746520536179");
	let mut messageE: noiseexplorer_xn::MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage(&mut messageE) {
		validE = true;
	}
	let tE: Vec<u8> = decode_str("c9df700a1e9c118572703d0d7f55c33fe4b07be30914a7a804a4cd6fdae90a486e");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b");
	let mut messageF: noiseexplorer_xn::MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage(&mut messageF) {
		validF = true;
	}
	let tF: Vec<u8> = decode_str("e371be686b36e1a101a7989f805d8e1520fc031b3a4a6085df1e386da28bac940d615cd9bb");
	assert!(
		validA && validB && validC && validD && validE && validF,
		"Sanity check FAIL for XN_25519_ChaChaPoly_BLAKE2s."
	);
	let mut cA: Vec<u8> = Vec::new();
	cA.append(&mut Vec::from(&messageA.ne[..]));
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::new();
	cB.append(&mut Vec::from(&messageB.ne[..]));
	cB.append(&mut messageB.ciphertext);
	let mut cC: Vec<u8> = Vec::new();
	cC.append(&mut messageC.ns);
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
