#![allow(non_snake_case, non_upper_case_globals, unused_imports)]

use noiseexplorer_x1x::{
	noisesession::NoiseSession,
	types::{Keypair, Message, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_x1x() {
    if let Ok(prologue) = Message::from_str("4a6f686e2047616c74") {
	if let Ok(init_static_private) = PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1") {
	if let Ok(resp_static_private) = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893") {
	if let Ok(init_static_kp) = Keypair::from_private_key(init_static_private) {
	if let Ok(resp_static_kp) = Keypair::from_private_key(resp_static_private) {
	
let mut initiator_session: NoiseSession = NoiseSession::init_session(true, prologue.clone(), init_static_kp);
	let mut responder_session: NoiseSession = NoiseSession::init_session(false, prologue, resp_static_kp);
	if let Ok(initiator_ephemeral_private) = PrivateKey::from_str("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a") {
if let Ok(init_ephemeral_kp) = Keypair::from_private_key(initiator_ephemeral_private) {
initiator_session.set_ephemeral_keypair(init_ephemeral_kp);
	if let Ok(responder_ephemeral_private) = PrivateKey::from_str("4a6f686e2047616c74") {
if let Ok(responder_ephemeral_kp) = Keypair::from_private_key(responder_ephemeral_private) {
responder_session.set_ephemeral_keypair(responder_ephemeral_kp);
	if let Ok(mA) = Message::from_str("4c756477696720766f6e204d69736573") {
	if let Ok(tA) = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573") {
	if let Ok(messageA) = initiator_session.send_message(mA) {
	if let Ok(_x) = responder_session.recv_message(messageA.clone()) {
	if let Ok(mB) = Message::from_str("4d757272617920526f746862617264") {
	if let Ok(tB) = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843c14ed87d71f6a5286c321a6ac22e7f0b85fb2a1b40859089994ae06f94f692259561cf304e4f3cc18daafc0c85fd8ec8cd9a426d671623e709e67fdb0877e3ad2e22921e76af180a73dce26b79ad4e") {
	if let Ok(messageB) = responder_session.send_message(mB) {
	if let Ok(_x) = initiator_session.recv_message(messageB.clone()) {
	if let Ok(mC) = Message::from_str("462e20412e20486179656b") {
	if let Ok(tC) = Message::from_str("1d33930ae43c1bc5ae4c225c5f13950b7f4bdacd7f8fc5712d5dd081559c0b25470c7581ecd7ce7f3cafa86215e47acc13218ddbf4472b809c3a02844cb4a3acdd329e7ba04f3369c0794f") {
	if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("61564d776e2fde84c05108b7f86503e4888a490ecb3f0b7d409c9d") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("a56223d4b114ea9f948e68d5805b8e967a72395f7e4e49aca2ae7256a65bc09824") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("c024436d821334b52ca5a1ec9ccab54b2071c14ea98778f8fbd1e9c5c4bcd2225a4d6bc91d") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}
	}}}}}}}}}}}}}}}}}}}}}}}}}}}}}
}
