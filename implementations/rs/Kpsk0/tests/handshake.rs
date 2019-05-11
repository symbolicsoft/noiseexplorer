#![allow(non_snake_case, non_upper_case_globals)]

use noiseexplorer_kpsk0::{noisesession::NoiseSession,
                          types::{Keypair, Message, PrivateKey, Psk, PublicKey}};

#[test]
fn noiseexplorer_test_kpsk0() {
	if let Ok(prologue,) = Message::from_str("4a6f686e2047616c74",) {
		if let Ok(init_static_private,) = PrivateKey::from_str(
			"e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1",
		) {
			if let Ok(resp_static_private,) = PrivateKey::from_str(
				"4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893",
			) {
				if let Ok(resp_static_public,) = resp_static_private.generate_public_key() {
					if let Ok(init_static_public_key,) = init_static_private.generate_public_key() {
						if let Ok(init_static_kp,) = Keypair::from_private_key(init_static_private,)
						{
							if let Ok(resp_static_kp,) =
								Keypair::from_private_key(resp_static_private,)
							{
								if let Ok(psk,) = Psk::from_str(
									"54686973206973206d7920417573747269616e20706572737065637469766521",
								) {
									let mut initiator_session: NoiseSession =
										NoiseSession::init_session(
											true,
											prologue.clone(),
											init_static_kp,
											resp_static_public,
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
											initiator_session
												.set_ephemeral_keypair(init_ephemeral_kp,);

											if let Ok(mA,) = Message::from_str(
												"4c756477696720766f6e204d69736573",
											) {
												if let Ok(tA,) = Message::from_str(
													"ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79443b0588c609a0bd9a0fb1d3d84bc37d74f73c8129a00a76a49227b64fdac65b59",
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
																	"1696d649da9b1097e75bdba3769aa2861bad1de0ed782b7be6dd2b0ef56960",
																) {
																	if let Ok(messageB,) =
																		responder_session
																			.send_message(mB,)
																	{
																		if let Ok(_x,) =
																			initiator_session
																				.recv_message(
																					messageB
																						.clone(),
																				) {
																			if let Ok(mC,) =
																				Message::from_str(
																					"462e20412e20486179656b",
																				) {
																				if let Ok(tC) = Message::from_str("e3a19dbc2d8e912e4e79ebbf4df96e06b6a98de3ef59abbf3be526") {
	if let Ok(messageC) = initiator_session.send_message(mC) {
	if let Ok(_x) = responder_session.recv_message(messageC.clone()) {
	if let Ok(mD) = Message::from_str("4361726c204d656e676572") {
	if let Ok(tD) = Message::from_str("e7d5f5db72092c35b70848efb126fb4a5910fc97b63e5e3eb7b2b6") {
	if let Ok(messageD) = responder_session.send_message(mD) {
	if let Ok(_x) = initiator_session.recv_message(messageD.clone()) {
	if let Ok(mE) = Message::from_str("4a65616e2d426170746973746520536179") {
	if let Ok(tE) = Message::from_str("32247d5e7da91884952be4b0623b6390fb4ff40175fa84df79387d840cf16a72e8") {
	if let Ok(messageE) = initiator_session.send_message(mE) {
	if let Ok(_x) = responder_session.recv_message(messageE.clone()) {
	if let Ok(mF) = Message::from_str("457567656e2042f6686d20766f6e2042617765726b") {
	if let Ok(tF) = Message::from_str("f06db65fb64b63764f82cbb628205620b55bc3900c7fbeaeb4c649e389d1c5a40b17455d1e") {
	if let Ok(messageF) = responder_session.send_message(mF) {
	if let Ok(_x) = initiator_session.recv_message(messageF.clone()) {
	assert!(tA == messageA, "\n\n\nTest A: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tA, messageA);
	assert!(tB == messageB, "\n\n\nTest B: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tB, messageB);
	assert!(tC == messageC, "\n\n\nTest C: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tC, messageC);
	assert!(tD == messageD, "\n\n\nTest D: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tD, messageD);
	assert!(tE == messageE, "\n\n\nTest E: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tE, messageE);
	assert!(tF == messageF, "\n\n\nTest F: FAIL\n\nExpected:\n{:X?}\n\nActual:\n{:X?}", tF, messageF);
	}}}}}
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
