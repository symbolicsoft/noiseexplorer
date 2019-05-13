#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_x1k::{
    noisesession::NoiseSession,
    types::{Keypair, Message, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_x1k() {
    if let Ok(prologue) = Message::from_str("4a6f686e2047616c74") {
        if let Ok(init_static_private) =
            PrivateKey::from_str("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1")
        {
            if let Ok(resp_static_private) = PrivateKey::from_str(
                "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
            ) {
                if let Ok(resp_static_public) = resp_static_private.generate_public_key() {
                    if let Ok(init_static_kp) = Keypair::from_private_key(init_static_private) {
                        if let Ok(resp_static_kp) = Keypair::from_private_key(resp_static_private) {
                            let mut initiator_session: NoiseSession = NoiseSession::init_session(
                                true,
                                prologue.clone(),
                                init_static_kp,
                                resp_static_public,
                            );
                            let mut responder_session: NoiseSession = NoiseSession::init_session(
                                false,
                                prologue,
                                resp_static_kp,
                                PublicKey::empty(),
                            );
                            if let Ok(initiator_ephemeral_private) = PrivateKey::from_str(
                                "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
                            ) {
                                if let Ok(init_ephemeral_kp) =
                                    Keypair::from_private_key(initiator_ephemeral_private)
                                {
                                    initiator_session.set_ephemeral_keypair(init_ephemeral_kp);
                                    if let Ok(responder_ephemeral_private) =
                                        PrivateKey::from_str("4a6f686e2047616c74")
                                    {
                                        if let Ok(responder_ephemeral_kp) =
                                            Keypair::from_private_key(responder_ephemeral_private)
                                        {
                                            responder_session
                                                .set_ephemeral_keypair(responder_ephemeral_kp);
                                            if let Ok(mA) = Message::from_str(
                                                "4c756477696720766f6e204d69736573",
                                            ) {
                                                if let Ok(tA) = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944a175ecb6df0c9d1986db9543b96d60c240c19f9a373a8aa5451ca32e4a5608f8") {
	if let Ok(messageA) = initiator_session.send_message(mA) {
	if let Ok(_x) = responder_session.recv_message(messageA.clone()) {
	if let Ok(mB) = Message::from_str("4d757272617920526f746862617264") {
	if let Ok(tB) = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843c3e3deddc0219e7777000606fee22f8151e10720c99656f7e27c114704b278") {
	if let Ok(messageB) = responder_session.send_message(mB) {
	if let Ok(_x) = initiator_session.recv_message(messageB.clone()) {
	if let Ok(mC) = Message::from_str("462e20412e20486179656b") {
	if let Ok(tC) = Message::from_str("54434d5b1ef60a94688c489e676732cc2ce28b213d577cc6bc7c31dfebce15ccc24321adbf4cf969082fc0610273a418b59c6372be1942810317efb69b92ae9b2281fd64c704f6627ac680") {
	if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("e0ba8f7528de232c25cefab7e73b563889c58ecd8a7dea244ba693") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("c443ad38b6772a329e78177bf7771cce331fda94880fc7545b928c82547871de02") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("62ecce974d09a08aa4c86cbc46ba96b34aeff12bdd70605d2449521b2ca3e11156cd8b3e0c") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}}
	}}}}}}}}}}}}}}}}}}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
