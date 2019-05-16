#![allow(non_snake_case, non_upper_case_globals, unused_imports)]

use noiseexplorer_ixpsk2::{
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey, Psk},
};

#[test]
fn noiseexplorer_test_ixpsk2() {
    if let Ok(prologue) = Message::from_str("4a6f686e2047616c74") {
	if let Ok(init_static_private) = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1") {
	if let Ok(resp_static_private) = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893") {
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
	if let Ok(mA) = Message::from_str("4c756477696720766f6e204d69736573") {
	if let Ok(tA) = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944c8d2ef6130dbd187858adbd6cbf5281bcbd8ed8253e496e2be8f83c38a03ae1075e06f2fd04fe41b76a52f2b9ed57fbdd1c3c468603b6d942fe1568198a424d65e64498e9ccd9441632cafad7ce6eb5a") {
	if let Ok(messageA) = initiator_session.send_message(mA) {
	if let Ok(_x) = responder_session.recv_message(messageA.clone()) {
	if let Ok(mB) = Message::from_str("4d757272617920526f746862617264") {
	if let Ok(tB) = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843558e79dd0608c24bb316b7fc9d9bf26bcb90e1cd3020e2bac84a563d7bd2bff4f29d1354443b13730c5828e687fc5de3964690435faef56fcc0449b352a6b8ba6abf71077221a40ad8030f431e4601") {
	if let Ok(messageB) = responder_session.send_message(mB) {
	if let Ok(_x) = initiator_session.recv_message(messageB.clone()) {
	if let Ok(mC) = Message::from_str("462e20412e20486179656b") {
	if let Ok(tC) = Message::from_str("cdd4dfd488c6958f8c12f622b4a73e771037d9d7b04df36292bad5") {
	if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("79b9b105e77aa3b1960f2369d31bd2d771bd327dbcf4b7339aa040") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("5a51ac5826e9cdeb8c1f53fa098f443ad7caceebb0201390a05612275d456cd1df") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("c69fa1a246b2dfe63b4c006ef602bea55a44f68c1826fe6c82956110373ce50863cd3abf50") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}}
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}
