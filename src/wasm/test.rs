#![allow(non_snake_case, non_upper_case_globals, unused_assignments, unused_imports)]
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

use noiseexplorer_$NOISE2WASM_N$_wasm::{
	consts::{DHLEN, MAC_LENGTH},
	error::NoiseError,
	noisesession::NoiseSession,
	types::{Keypair, PrivateKey, PublicKey, Psk},
};
use std::str::FromStr;

fn decode_str(s: &str) -> Vec<u8> {
 	hex::decode(s).unwrap()
 }

#[wasm_bindgen_test]
fn noiseexplorer_test_$NOISE2WASM_N$() {

	let mut prologue: Vec<u8> = Vec::new();
	let mut messageA: Vec<u8> = Vec::new();	
	let mut messageB: Vec<u8> = Vec::new();
	let mut messageC: Vec<u8> = Vec::new();
	let mut messageD: Vec<u8> = Vec::new();	
	let mut messageE: Vec<u8> = Vec::new();
	let mut messageF: Vec<u8> = Vec::new();

	$NOISE2WASM_T$
}
