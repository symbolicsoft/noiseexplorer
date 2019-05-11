#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_x1n::{noisesession::NoiseSession,
                        types::{Keypair, Message, PrivateKey, PublicKey}};

#[test]
fn noiseexplorer_test_x1n() {
	if let Ok(prologue,) = Message::from_str("4a6f686e2047616c74",) {
		if let Ok(init_static_private,) = PrivateKey::from_str(
			"e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
		) {
			if let Ok(resp_static_private,) = PrivateKey::from_str(
				"0000000000000000000000000000000000000000000000000000000000000001",
			) {
				if let Ok(init_static_kp,) = Keypair::from_private_key(init_static_private,) {
					if let Ok(resp_static_kp,) = Keypair::from_private_key(resp_static_private,) {
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
										Keypair::from_private_key(responder_ephemeral_private,)
									{
										responder_session
											.set_ephemeral_keypair(responder_ephemeral_kp,);
										if let Ok(mA,) =
											Message::from_str("4c756477696720766f6e204d69736573",)
										{
											if let Ok(tA,) = Message::from_str(
												"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573",
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
															if let Ok(tB,) = Message::from_str(
																"95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d2a6d85157ee61d979741bf7295b2536d3b380b95ae967795c40cc048f6486",
															) {
																if let Ok(messageB,) =
																	responder_session
																		.send_message(mB,)
																{
																	if let Ok(_x,) =
																		initiator_session
																			.recv_message(
																				messageB.clone(),
																			) {
																		if let Ok(mC,) =
																			Message::from_str(
																				"462e20412e20486179656b",
																			) {
																			if let Ok(tC,) =
																				Message::from_str(
																					"ebfd2dff95b8d144f616212579ecf0faa109cc2de5af9e77d20bafaa1de70676c093cba24277162a3f6b6565a730604c75d3c2aae8f5e71564194e66f35cf4c2c86d7f66987f75ab0aa507",
																				) {
																				if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("5dc0e26bf720c7ce31c16e09aed6ca7fa78a6f3db0f190cf7a5e8c") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("1d85ff0ab94a7831237b6e9eb11a4ddff3ad1eb0f438d73105a350a90a35210995") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("d2781f144c47a5f83735111d330cc81380af9b0989e9416b5a34759dc0e24c47c589cf4c14") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}
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
