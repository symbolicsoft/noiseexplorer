#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_knpsk0::{noisesession::NoiseSession,
                           types::{Keypair, Message, PrivateKey, Psk, PublicKey}};

#[test]
fn noiseexplorer_test_knpsk0() {
	if let Ok(prologue,) = Message::from_str("4a6f686e2047616c74",) {
		if let Ok(init_static_private,) = PrivateKey::from_str(
			"e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
		) {
			if let Ok(resp_static_private,) = PrivateKey::from_str(
				"0000000000000000000000000000000000000000000000000000000000000001",
			) {
				if let Ok(init_static_public_key,) = init_static_private.generate_public_key() {
					if let Ok(init_static_kp,) = Keypair::from_private_key(init_static_private,) {
						if let Ok(resp_static_kp,) = Keypair::from_private_key(resp_static_private,)
						{
							if let Ok(psk,) = Psk::from_str(
								"54686973206973206d7920417573747269616e20706572737065637469766521",
							) {
								let mut initiator_session: NoiseSession =
									NoiseSession::init_session(
										true,
										prologue.clone(),
										init_static_kp,
										PublicKey::empty(),
										psk.clone(),
									);
								let mut responder_session: NoiseSession =
									NoiseSession::init_session(
										false,
										prologue,
										resp_static_kp,
										init_static_public_key,
										psk,
									);
								if let Ok(initiator_ephemeral_private,) = PrivateKey::from_str(
									"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
								) {
									if let Ok(init_ephemeral_kp,) =
										Keypair::from_private_key(initiator_ephemeral_private,)
									{
										initiator_session.set_ephemeral_keypair(init_ephemeral_kp,);
										if let Ok(responder_ephemeral_private,) =
											PrivateKey::from_str("4a6f686e2047616c74",)
										{
											if let Ok(responder_ephemeral_kp,) =
												Keypair::from_private_key(
													responder_ephemeral_private,
												) {
												responder_session
													.set_ephemeral_keypair(responder_ephemeral_kp,);
												if let Ok(mA,) = Message::from_str(
													"4c756477696720766f6e204d69736573",
												) {
													if let Ok(tA,) = Message::from_str(
														"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794483acf0be48f87c43c498f486d7c1874d0747701aa7ec7ab1e36f83c59f9fbb13",
													) {
														if let Ok(messageA,) =
															initiator_session.send_message(mA,)
														{
															if let Ok(_x,) = responder_session
																.recv_message(messageA.clone(),)
															{
																if let Ok(mB,) = Message::from_str(
																	"4d757272617920526f746862617264",
																) {
																	if let Ok(tB,) =
																		Message::from_str(
																			"95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088439beb9a4b1f2306829aa2435daf14cb7f154f143feae1b87bc93c90fd5496e1",
																		) {
																		if let Ok(messageB,) =
																			responder_session
																				.send_message(mB,)
																		{
																			if let Ok(_x,) =
																				initiator_session
																					.recv_message(
																						messageB
																							.clone(
																							),
																					) {
																				if let Ok(mC) = Message::from_str("462e20412e20486179656b") {
	if let Ok(tC) = Message::from_str("f80c04074a17c90c01c97433b4f7b133f9495dfc1e7b1505a825fd") {
	if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("cf2fffd0b7b3218b93a7c3b3952e48add6853e9012f050df974642") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("3d6cf45526f1e3fbbfcf4d653a99bdd25429895e347fc41e5b6af8d5d0f8abee63") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("5cca487eecaeecd6025c5e7ee0cb89a6862c847b6ac42cfb577bf58a3e30b7eab1b7996258") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}}}
	}}}}}}}}}}
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
							}
						}
					}
				}
			}
		}
	}
}
