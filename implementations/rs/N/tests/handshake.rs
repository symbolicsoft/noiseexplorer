#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_n::{noisesession::NoiseSession,
                      types::{Keypair, Message, PrivateKey, PublicKey}};

#[test]
fn noiseexplorer_test_n() {
	if let Ok(prologue,) = Message::from_str("4a6f686e2047616c74",) {
		if let Ok(init_static_private,) = PrivateKey::from_str(
			"0000000000000000000000000000000000000000000000000000000000000001",
		) {
			if let Ok(resp_static_private,) = PrivateKey::from_str(
				"4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
			) {
				if let Ok(resp_static_public,) = resp_static_private.generate_public_key() {
					if let Ok(init_static_kp,) = Keypair::from_private_key(init_static_private,) {
						if let Ok(resp_static_kp,) = Keypair::from_private_key(resp_static_private,)
						{
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
							if let Ok(initiator_ephemeral_private,) = PrivateKey::from_str(
								"893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a",
							) {
								if let Ok(init_ephemeral_kp,) =
									Keypair::from_private_key(initiator_ephemeral_private,)
								{
									initiator_session.set_ephemeral_keypair(init_ephemeral_kp,);

									if let Ok(mA,) =
										Message::from_str("4c756477696720766f6e204d69736573",)
									{
										if let Ok(tA,) = Message::from_str(
											"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79441b168ed8bbe8220b52bbbde6593d109d78c299b567f6e69276efcf2659c39073",
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
															"a7b5d1962001e9c4d965ea5f133941e9e6989094bcde637a582c34b954f34a",
														) {
															if let Ok(messageB,) =
																responder_session.send_message(mB,)
															{
																if let Ok(_x,) = initiator_session
																	.recv_message(messageB.clone(),)
																{
																	if let Ok(mC,) =
																		Message::from_str(
																			"462e20412e20486179656b",
																		) {
																		if let Ok(tC,) =
																			Message::from_str(
																				"16ff2557d5d671abe58c88d2a31b58e3a494ab3a6498124be0ea3f",
																			) {
																			if let Ok(messageC,) =
																				initiator_session
																					.send_message(
																						mC,
																					) {
																				if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("1a6e85b0ef71c38db2c2bf3ebef1d41dc93e26bea6899187d5633d") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("00ad2b7d0a03a748d0aefd3accee7bbbcc0bb0ed64d685b2ee8af78997a0245e3f") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("5631105c749b9550b27d7926dec0c5b83d4bf207688deccd51b50dd7fc9d5e337bba9c3177") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}
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
