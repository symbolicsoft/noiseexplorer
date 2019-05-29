/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

use crate::{consts::{HASHLEN, MAC_LENGTH, MAX_MESSAGE},
			error::NoiseError,
			state::{CipherState, HandshakeState},
			types::{Hash, Keypair, Psk, PublicKey}};
/// A `NoiseSession` object is used to keep track of the states of both local
/// and remote parties before, during, and after a handshake.
///
/// It contains:
/// - `h`:  Stores the handshake hash output after a successful handshake in a
///   Hash object. Is initialized as array of 0 bytes.
/// - `mc`:  Keeps track of the total number of incoming and outgoing messages,
///   including those sent during a handshake.
/// - `i`: `bool` value that indicates whether this session corresponds to the
///   local or remote party.
/// - `hs`: Keeps track of the local party's state while a handshake is being
///   performed.
/// - `cs1`: Keeps track of the local party's post-handshake state. Contains a
///   cryptographic key and a nonce.
/// - `cs2`: Keeps track of the remote party's post-handshake state. Contains a
///   cryptographic key and a nonce.
#[derive(Clone)]
pub struct NoiseSession {
	hs:  HandshakeState,
	h:   Hash,
	cs1: CipherState,
	cs2: CipherState,
	mc:  u128,
	i:   bool,
	is_transport: bool,
}
impl NoiseSession {
	/// Returns `true` if a handshake has been successfully performed and the session is in transport mode, or false otherwise.
	pub fn is_transport(&self) -> bool {
		self.is_transport
	}
	/// Clears `cs1`.
	pub fn clear_local_cipherstate(&mut self) {
		self.cs1.clear();
	}

	/// Clears `cs2`.
	pub fn clear_remote_cipherstate(&mut self) {
		self.cs2.clear();
	}

	/// `NoiseSession` destructor function.
	pub fn end_session(mut self) {
		self.hs.clear();
		self.clear_local_cipherstate();
		self.clear_remote_cipherstate();
		self.cs2.clear();
		self.mc = 0;
		self.h = Hash::new();
	}

	/// Returns `h`.
	pub fn get_handshake_hash(&self) -> Option<[u8; HASHLEN]> {
		if self.is_transport {
			return Some(self.h.as_bytes());
		}
			None
	}

	/// Sets the value of the local ephemeral keypair as the parameter `e`.
	pub fn set_ephemeral_keypair(&mut self, e: Keypair) {
		self.hs.set_ephemeral_keypair(e);
	}

	pub fn get_remote_static_public_key(&self) -> PublicKey {
		self.hs.get_remote_static_public_key()
	}


	/// Instantiates a `NoiseSession` object. Takes the following as parameters:
	/// - `initiator`: `bool` variable. To be set as `true` when initiating a handshake with a remote party, or `false` otherwise.
	/// - `prologue`: `Message` object. Could optionally contain the name of the protocol to be used.
	/// - `s`: `Keypair` object. Contains local party's static keypair.
	/// - `rs`: `Option<PublicKey>`. Contains the remote party's static public key.	Tip: use `Some(rs_value)` in case a remote static key exists and `None` otherwise.
	/// - `psk`: `Psk` object. Contains the pre-shared key.
	pub fn init_session(initiator: bool, prologue: &[u8], s: Keypair, rs: Option<PublicKey>, psk: Psk) -> NoiseSession {
		if initiator {
			NoiseSession{
				hs: HandshakeState::initialize_initiator(prologue, s, rs.unwrap_or(PublicKey::empty()), psk),
				mc: 0,
				i: initiator,
				cs1: CipherState::new(),
				cs2: CipherState::new(),
				h: Hash::new(),
				is_transport: false,
			}
		} else {
			NoiseSession {
				hs: HandshakeState::initialize_responder(prologue, s, psk),
				mc: 0,
				i: initiator,
				cs1: CipherState::new(),
				cs2: CipherState::new(),
				h: Hash::new(),
				is_transport: false,
			}
		}
	}
	
	/// Takes a `Message` object containing plaintext, and an output placeholder `&[u8]` as parameters.
	/// Returns a `Ok(usize)` object containing the size of the corresponding ciphertext upon successful encryption, and `Err(NoiseError)` otherwise
	///
	/// _Note that while `mc` <= 1 the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._
	pub fn send_message(&mut self, in_out: &mut [u8]) -> Result<(), NoiseError> {
		if in_out.len() < MAC_LENGTH || in_out.len() > MAX_MESSAGE {
			return Err(NoiseError::UnsupportedMessageLengthError);
		}
		if self.mc == 0 {
			self.hs.write_message_a(in_out)?;
		}
		else if self.mc == 1 {
			let temp = self.hs.write_message_b(in_out)?;
			self.h = temp.0;
			self.is_transport = true;
			self.cs1 = temp.1;
			self.cs2 = temp.2;
			self.hs.clear();
		} else if self.i {
			self.cs1.write_message_regular(in_out)?;
		} else {
			self.cs2.write_message_regular(in_out)?;
		}
		self.mc += 1;
		Ok(())
	}
	
	/// Takes a `Message` object received from the remote party, and an output placeholder `&[u8]` as parameters.
	/// Returns a `Ok(usize)` object containing the size of the plaintext, and `Err(NoiseError)` otherwise.
	///
	/// _Note that while `mc` <= 1 the ciphertext will be included as a payload for handshake messages and thus will not offer the same guarantees offered by post-handshake messages._
	pub fn recv_message(&mut self, in_out: &mut [u8]) -> Result<(), NoiseError> {
		if in_out.len() < MAC_LENGTH || in_out.len() > MAX_MESSAGE {
			return Err(NoiseError::UnsupportedMessageLengthError);
		}
		if self.mc == 0 {
			self.hs.read_message_a(in_out)?;
		}
		else if self.mc == 1 {
			let temp = self.hs.read_message_b(in_out)?;
				self.h = temp.0;
			self.is_transport = true;
				self.cs1 = temp.1;
				self.cs2 = temp.2;
				self.hs.clear();
		} else if self.i {
			self.cs2.read_message_regular(in_out)?;
		} else {
				self.cs1.read_message_regular(in_out)?;
		}
		self.mc += 1;
		Ok(())
	}
}
