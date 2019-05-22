/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

use crate::{consts::HASHLEN,
            error::NoiseError,
            state::{CipherState, HandshakeState},
            types::{Hash, Keypair, Message, Psk, PublicKey}};
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
}
impl NoiseSession {
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
	pub fn get_handshake_hash(&self) -> [u8; HASHLEN] {
		self.h.as_bytes()
	}

	/// Sets the value of the local ephemeral keypair as the parameter `e`.
	pub fn set_ephemeral_keypair(&mut self, e: Keypair) {
		self.hs.set_ephemeral_keypair(e);
	}

      pub fn get_remote_static_public_key(&self) -> PublicKey {
         self.hs.get_remote_static_public_key()
     }

/* $NOISE2RS_P$ */
}
