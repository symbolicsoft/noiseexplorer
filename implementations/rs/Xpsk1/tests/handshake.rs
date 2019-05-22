#![allow(non_snake_case, non_upper_case_globals, unused_imports)]

use noiseexplorer_xpsk1::{
	consts::DHLEN,
	error::NoiseError,
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey, Psk},
};

fn decode_str(s: &str) -> Vec<u8> {
 	hex::decode(s).unwrap()
 }

#[test]
fn noiseexplorer_test_xpsk1() {
    let mut buffer = [0u8; 65535];
	if let Ok(prologue) = Message::from_bytes(&decode_str("4a6f686e2047616c74")[..]) {
	if let Ok(init_static_private) = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1") {
	if let Ok(resp_static_private) = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893") {
	if let Ok(resp_static_public) = resp_static_private.generate_public_key() { 
	if let Ok(init_static_kp) = Keypair::from_private_key(init_static_private) {
	if let Ok(resp_static_kp) = Keypair::from_private_key(resp_static_private) {
	if let Ok(psk) = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521") {
	
let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologue.clone(), init_static_kp, Some(resp_static_public), psk.clone());
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologue, resp_static_kp, None, psk);
	if let Ok(initiator_ephemeral_private) = PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a") {
if let Ok(init_ephemeral_kp) = Keypair::from_private_key(initiator_ephemeral_private) {
initiator_session.set_ephemeral_keypair(init_ephemeral_kp);
	
	if let Ok(mA) = Message::from_bytes(&decode_str("4c756477696720766f6e204d69736573")[..]) {
	if let Ok(tA) = Message::from_bytes(&decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479be957c06c64483c69607f17a61f440528418499b7f686adfb8091fb03643ac32b5823d51c15e00d9355d5623c817a552a0bb264052946463c288d45d9ede7c6ea227faafbb5f1dd11166d6ad3f7cc5")[..]) {
	if let Ok(_x) = initiator_session.send_message(mA, &mut buffer[..]) {
	if let Ok(messageA) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = responder_session.recv_message(messageA.clone(), &mut buffer[..]) {
	if let Ok(mB) = Message::from_bytes(&decode_str("4d757272617920526f746862617264")[..]) {
	if let Ok(tB) = Message::from_bytes(&decode_str("cfbc17a5950121da51b421b0f95dbaa4745e70477be8da8871edd89049f998")[..]) {
	if let Ok(_x) = responder_session.send_message(mB, &mut buffer[..]) {
	if let Ok(messageB) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = initiator_session.recv_message(messageB.clone(), &mut buffer[..]) {
	if let Ok(mC) = Message::from_bytes(&decode_str("462e20412e20486179656b")[..]) {
	if let Ok(tC) = Message::from_bytes(&decode_str("a6a910d1067d991c63e8520bf327fa1f530a74fb47c58b8e3ff2a9")[..]) {
	if let Ok(_x) = initiator_session.send_message(mC, &mut buffer[..]) {
	if let Ok(messageC) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone(), &mut buffer[..]) {
	if let Ok(mD) = Message::from_bytes(&decode_str("4361726c204d656e676572")[..]) {
	if let Ok(tD) = Message::from_bytes(&decode_str("b7cf2eb3291ef4b09514aa0f67ffc8b31cb1b2a323631bab0506c8")[..]) {
	if let Ok(_x) = responder_session.send_message(mD, &mut buffer[..]) {
	if let Ok(messageD) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone(), &mut buffer[..]) {
	if let Ok(mE) = Message::from_bytes(&decode_str("4a65616e2d426170746973746520536179")[..]) {
	if let Ok(tE) = Message::from_bytes(&decode_str("70ed51f6d218aa0d44a229ea4a6961d154f92868f832cb2471287e8af49460de90")[..]) {
	if let Ok(_x) = initiator_session.send_message(mE, &mut buffer[..]) {
	if let Ok(messageE) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone(), &mut buffer[..]) {
	if let Ok(mF) = Message::from_bytes(&decode_str("457567656e2042f6686d20766f6e2042617765726b")[..]) {
	if let Ok(tF) = Message::from_bytes(&decode_str("2abf8cc72678e7c569817896cfddca8247274a794be86ac4e9b0a754f9332cf8ed784da75a")[..]) {
	if let Ok(_x) = responder_session.send_message(mF, &mut buffer[..]) {
	if let Ok(messageF) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone(), &mut buffer[..]) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}
