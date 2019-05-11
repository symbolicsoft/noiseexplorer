#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_xx::{noisesession::NoiseSession,
                       types::{Keypair, Message, PrivateKey, PublicKey}};

#[test]
fn noiseexplorer_test_xx() {
	if let Ok(prologue,) = Message::from_str("4a6f686e2047616c74",) {
		if let Ok(init_static_private,) = PrivateKey::from_str(
			"e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
		) {
			if let Ok(resp_static_private,) = PrivateKey::from_str(
				"4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
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
																"95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec55a2298d2dbff80eff034d20595153f63a196a6cead1e11b2bb13e336fa13616dd3e8b0a070c882ed3f1a78c7c06c93",
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
																					"46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d415b670c114f79b9a4f80541570f77ce88802efa4220cff733e7b5668ba38059ec904b4b8eef9448085faf51",
																				) {
																				if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("d5e83adfaac5dc324a68f1862df54549e56d209fba707205f328b2") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("d102c9029b1f55c788f561ba7737afbccef9c9f1bf2f238167fd40ba9c1c134867") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("cb1ce80960382c6d5d5e740ffb724d1432f0310b200fb6f8424120f506092744baa415e155") {
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
