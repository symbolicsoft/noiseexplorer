#![allow(non_snake_case, non_upper_case_globals, unused_imports)]

use noiseexplorer_inpsk2::{
	consts::DHLEN,
	error::NoiseError,
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey, Psk},
};

fn decode_str(s: &str) -> Vec<u8> {
 	hex::decode(s).unwrap()
 }

#[test]
fn noiseexplorer_test_inpsk2() {
    let mut buffer = [0u8; 65535];
	if let Ok(prologue) = Message::from_bytes(&decode_str("4a6f686e2047616c74")[..]) {
	if let Ok(init_static_private) = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1") {
	if let Ok(resp_static_private) = PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001") {
	if let Ok(init_static_kp) = Keypair::from_private_key(init_static_private) {
	if let Ok(resp_static_kp) = Keypair::from_private_key(resp_static_private) {
	if let Ok(psk) = Psk::from_str("54686973206973206d7920417573747269616e20706572737065637469766521") {
	
let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologue.clone(), init_static_kp, psk.clone());
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologue, resp_static_kp, psk);
	if let Ok(initiator_ephemeral_private) = PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a") {
if let Ok(init_ephemeral_kp) = Keypair::from_private_key(initiator_ephemeral_private) {
initiator_session.set_ephemeral_keypair(init_ephemeral_kp);
	if let Ok(responder_ephemeral_private) = PrivateKey::from_str("4a6f686e2047616c74") {
if let Ok(responder_ephemeral_kp) = Keypair::from_private_key(responder_ephemeral_private) {
responder_session.set_ephemeral_keypair(responder_ephemeral_kp);
	if let Ok(mA) = Message::from_bytes(&decode_str("4c756477696720766f6e204d69736573")[..]) {
	if let Ok(tA) = Message::from_bytes(&decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794433ebdb3ea81aa07d44de08a018ddf003b4bd6940108601702597bcbc51ca4911757720089ea5558c01e08672a172df4841717c72ac72e9250f6e761c187c19f0872e3dad40c431da18d78f6751a0c303")[..]) {
	if let Ok(_x) = initiator_session.send_message(mA, &mut buffer[..]) {
	if let Ok(messageA) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = responder_session.recv_message(messageA.clone(), &mut buffer[..]) {
	if let Ok(mB) = Message::from_bytes(&decode_str("4d757272617920526f746862617264")[..]) {
	if let Ok(tB) = Message::from_bytes(&decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088438868e7df37d23588e3372133ac0f86dd8bc5af7dfb3a16fda77a760862e665")[..]) {
	if let Ok(_x) = responder_session.send_message(mB, &mut buffer[..]) {
	if let Ok(messageB) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = initiator_session.recv_message(messageB.clone(), &mut buffer[..]) {
	if let Ok(mC) = Message::from_bytes(&decode_str("462e20412e20486179656b")[..]) {
	if let Ok(tC) = Message::from_bytes(&decode_str("bb506f7e9982f8dadd94bd9b118f86ae126b7b8f67429a296c66d7")[..]) {
	if let Ok(_x) = initiator_session.send_message(mC, &mut buffer[..]) {
	if let Ok(messageC) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone(), &mut buffer[..]) {
	if let Ok(mD) = Message::from_bytes(&decode_str("4361726c204d656e676572")[..]) {
	if let Ok(tD) = Message::from_bytes(&decode_str("cec1423051a567b0c4fbcdaf85820abb6e9930a64a24d3b9aa3716")[..]) {
	if let Ok(_x) = responder_session.send_message(mD, &mut buffer[..]) {
	if let Ok(messageD) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone(), &mut buffer[..]) {
	if let Ok(mE) = Message::from_bytes(&decode_str("4a65616e2d426170746973746520536179")[..]) {
	if let Ok(tE) = Message::from_bytes(&decode_str("9f232e89164755ad63919c90c2de142fc9ec03ac0a15734eaf9895ed7bbff0a06b")[..]) {
	if let Ok(_x) = initiator_session.send_message(mE, &mut buffer[..]) {
	if let Ok(messageE) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone(), &mut buffer[..]) {
	if let Ok(mF) = Message::from_bytes(&decode_str("457567656e2042f6686d20766f6e2042617765726b")[..]) {
	if let Ok(tF) = Message::from_bytes(&decode_str("0829c89da7c7fd9a8225b9e2f0c5eaa49d7d312c1ca72a881f2ecfd1d307ec093fd8420423")[..]) {
	if let Ok(_x) = responder_session.send_message(mF, &mut buffer[..]) {
	if let Ok(messageF) = Message::from_bytes(&buffer.clone()[..]) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone(), &mut buffer[..]) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}}
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}
