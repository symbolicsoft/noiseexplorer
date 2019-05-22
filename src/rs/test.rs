#![allow(non_snake_case, non_upper_case_globals, unused_imports)]

use noiseexplorer_$NOISE2RS_N$::{
	consts::DHLEN,
	error::NoiseError,
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey$NOISE2RS_S$},
};

fn decode_str(s: &str) -> Vec<u8> {
 	hex::decode(s).unwrap()
 }

#[test]
fn noiseexplorer_test_$NOISE2RS_N$() {
    let mut buffer = [0u8; 65535];
	$NOISE2RS_T$
}
