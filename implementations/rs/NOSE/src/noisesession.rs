/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

use crate::{
    state::{CipherState, HandshakeState},
    types::{Hash, Keypair, Message, MessageBuffer, Psk, PublicKey},
};

#[derive(Clone)]
pub struct NoiseSession {
    hs: HandshakeState,
    h: Hash,
    cs1: CipherState,
    cs2: CipherState,
    mc: u32,
    i: bool,
}
impl NoiseSession {
	pub fn set_ephemeral_keypair(&mut self, e: Keypair) {
        self.hs.set_ephemeral_keypair(e);
    }
	pub fn init_session(initiator: bool, prologue: Message, s: Keypair, rs: PublicKey) -> NoiseSession {
		if initiator {
			NoiseSession{
				hs: HandshakeState::initialize_initiator(&prologue.as_bytes(), s, rs, Psk::new()),
				mc: 0,
				i: initiator,
				cs1: CipherState::new(),
				cs2: CipherState::new(),
				h: Hash::new(),
			}
		} else {
			NoiseSession {
				hs: HandshakeState::initialize_responder(&prologue.as_bytes(), s, rs, Psk::new()),
				mc: 0,
				i: initiator,
				cs1: CipherState::new(),
				cs2: CipherState::new(),
				h: Hash::new(),
			}
		}
	}
	
	pub fn send_message(&mut self, message: Message) -> MessageBuffer {
		if self.mc == 0 {
			self.mc += 1;
			self.hs.write_message_a(&message.as_bytes()[..])
		}
		else if self.mc == 1 {
			let temp = self.hs.write_message_b(&message.as_bytes()[..]);
			self.h = temp.0;
			self.cs1 = temp.2;
			self.cs2 = temp.3;
			self.hs.clear();
			self.mc += 1;
			temp.1
		}
		else if self.i {
			let buffer = self.cs1.write_message_regular(&message.as_bytes()[..]);
			self.mc += 1;
			buffer
		} else {
			let buffer = self.cs2.write_message_regular(&message.as_bytes()[..]);
			self.mc += 1;
			buffer
		}
	}
	
	pub fn recv_message(&mut self, message: &mut MessageBuffer) -> Option<Vec<u8>> {
		let mut plaintext: Option<Vec<u8>> = None;
		if self.mc == 0 {
			plaintext = self.hs.read_message_a(message);
		}
		else if self.mc == 1 {
			if let Some(temp) = self.hs.read_message_b(message) {
				self.h = temp.0;
				plaintext = Some(temp.1);
				self.cs1 = temp.2;
				self.cs2 = temp.3;
				self.hs.clear();
			}
		}
		else if self.mc > 1 {
			if self.i {
				if let Some(msg) = &self.cs2.read_message_regular(message) {
					plaintext = Some(msg.to_owned());
				}
			} else if let Some(msg) = &self.cs1.read_message_regular(message) {
					plaintext = Some(msg.to_owned());
			}
		}
		self.mc += 1;
		plaintext
	}
}
