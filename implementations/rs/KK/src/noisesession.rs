/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

use crate::{
    consts::HASHLEN,
    state::{CipherState, HandshakeState},
    types::{Hash, Keypair, Message, Psk, PublicKey},
};
/// A `NoiseSession` object is used to keep track of the states of both local and remote parties before, during, and after a handshake.
///
/// It contains:
/// - `h`:  Stores the handshake hash output after a successful handshake in a Hash object. Is initialized as array of 0 bytes.
/// - `mc`:  Keeps track of the total number of incoming and outgoing messages, including those sent during a handshake.
/// - `i`: `bool` value that indicates whether this session corresponds to the local or remote party.
/// - `hs`: Keeps track of the local party's state while a handshake is being performed.
/// - `cs1`: Keeps track of the local party's post-handshake state. Contains a cryptographic key and a nonce.
/// - `cs2`: Keeps track of the remote party's post-handshake state. Contains a cryptographic key and a nonce.
#[derive(Clone)]
pub struct NoiseSession {
    hs: HandshakeState,
    h: Hash,
    cs1: CipherState,
    cs2: CipherState,
    mc: u128,
    i: bool,
}
impl NoiseSession {
    /// Clears `cs1`.
    pub fn clear_local_cipherstate (&mut self) {
        self.cs1.clear();
    }
    /// Clears `cs2`.
    pub fn clear_remote_cipherstate (&mut self) {
        self.cs2.clear();
    }
    /// `NoiseSession` destructor function.
    pub fn end_session (mut self) {
        self.hs.clear();
        self.clear_local_cipherstate();
        self.clear_remote_cipherstate();
        self.cs2.clear();
        self.mc = 0;
        self.h = Hash::new();
    }
    /// Returns `h`.
    pub fn get_handshake_hash(&self) -> [u8; HASHLEN] {
        self.h.as_bytes()
    }
    /// Sets the value of the local ephemeral keypair as the parameter `e`.
	pub fn set_ephemeral_keypair(&mut self, e: Keypair) {
        self.hs.set_ephemeral_keypair(e);
    }
	/// Instantiates a `NoiseSession` object. Takes the following as parameters:
	/// - `initiator`: `bool` variable. To be set as `true` when initiating a handshake with a remote party, or `false` otherwise.
	/// - `prologue`: `Message` object. Could optionally contain the name of the protocol to be used.
	/// - `s`: `Keypair` object. Contains local party's static keypair.
	/// - `rs`: `PublicKey` object. Contains the remote party's static public key.
	
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
	/// Takes a `Message` object containing plaintext as a parameter.
	/// Returns a `Vec<u8>` containing the corresponding ciphertext.
	///
	/// _Note that while `mc` <= 1 the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._
	
	pub fn send_message(&mut self, message: Message) -> Vec<u8> {
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
	/// Takes a `Vec<u8>` received from the remote party as a parameter.
	/// Returns an `Option<Vec<u8>>` containing plaintext upon successful decryption, and `None` otherwise.
	///
	/// _Note that while `mc` <= 1 the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._
	pub fn recv_message(&mut self, input: &mut Vec<u8>) -> Option<Vec<u8>> {
		let mut plaintext: Option<Vec<u8>> = None;
		if self.mc == 0 {
			plaintext = self.hs.read_message_a(input);
		}
		else if self.mc == 1 {
			if let Some(temp) = self.hs.read_message_b(input) {
				self.h = temp.0;
				plaintext = Some(temp.1);
				self.cs1 = temp.2;
				self.cs2 = temp.3;
				self.hs.clear();
			}
		}
		else if self.mc > 1 {
			if self.i {
				if let Some(msg) = &self.cs2.read_message_regular(input) {
					plaintext = Some(msg.to_owned());
				}
			} else if let Some(msg) = &self.cs1.read_message_regular(input) {
					plaintext = Some(msg.to_owned());
			}
		}
		self.mc += 1;
		plaintext
	}
}
