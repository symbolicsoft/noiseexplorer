#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_nx1::{
    noisesession::NoiseSession,
    types::{Keypair, Message, PrivateKey, PublicKey},
};

#[test]
fn noiseexplorer_test_nx1() {
    if let Ok(prologue) = Message::from_str("4a6f686e2047616c74") {
        if let Ok(init_static_private) =
            PrivateKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
        {
            if let Ok(resp_static_private) = PrivateKey::from_str(
                "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
            ) {
                if let Ok(init_static_kp) = Keypair::from_private_key(init_static_private) {
                    if let Ok(resp_static_kp) = Keypair::from_private_key(resp_static_private) {
                        let mut initiator_session: NoiseSession = NoiseSession::init_session(
                            true,
                            prologue.clone(),
                            init_static_kp,
                            PublicKey::empty(),
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
                                        if let Ok(mA) =
                                            Message::from_str("4c756477696720766f6e204d69736573")
                                        {
                                            if let Ok(tA) = Message::from_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573") {
	if let Ok(messageA) = initiator_session.send_message(mA) {
	if let Ok(_x) = responder_session.recv_message(messageA.clone()) {
	if let Ok(mB) = Message::from_str("4d757272617920526f746862617264") {
	if let Ok(tB) = Message::from_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088439b30cefd4ed5f364767278a44af908e027770a1bbb5cb73b4845623fde14f568c00acef543087cac6c296ac008b718035dcc25bdcbe85781484781f697bef836c7529d69c10129208d18141dfd84a8") {
	if let Ok(messageB) = responder_session.send_message(mB) {
	if let Ok(_x) = initiator_session.recv_message(messageB.clone()) {
	if let Ok(mC) = Message::from_str("462e20412e20486179656b") {
	if let Ok(tC) = Message::from_str("a123b0d1172ec45edda98b5e3728c9c08d3fc80bf90df75a07b185") {
	if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("0bd49626637293f0d0a610b56ba093c25e82c3d2c262020db10732") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("8a7582a7b69081ddbae8e89ea5e2da4154c368875dbac46e729564349c3acf5526") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("82b62e297aae61ab5d6903ad401b85f4d75dd9b71503cd830b8c82607a4a1dc808c4eee32f") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}
	}}}}}}}}}}}}}}}}}}}
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
