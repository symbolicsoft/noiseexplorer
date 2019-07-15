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
/// - `hs`: Keeps track of the local party's state while a handshake is being
///   performed.
/// - `h`:  Stores the handshake hash output after a successful handshake in a
///   Hash object. Is initialized as array of 0 bytes.
/// - `cs1`: Keeps track of the local party's post-handshake state. Contains a
///   cryptographic key and a nonce.
/// - `cs2`: Keeps track of the remote party's post-handshake state. Contains a
///   cryptographic key and a nonce.
/// - `mc`:  Keeps track of the total number of incoming and outgoing messages,
///   including those sent during a handshake.
/// - `i`: `bool` value that indicates whether this session corresponds to the
///   local or remote party.
/// - `is_transport`: `bool` value that indicates whether a handshake has been
///   performed succesfully with a remote session and the session is in transport mode.

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

	/// Calls the [Rekey](https://noiseprotocol.org/noise.html#rekey) method for `cs1`
	pub fn rekey_local_cipherstate(&mut self) {
		self.cs1.rekey()
	}

	/// Calls the [Rekey](https://noiseprotocol.org/noise.html#rekey) method for `cs2`
	pub fn rekey_remote_cipherstate(&mut self) {
		self.cs1.rekey()
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
	
	/// Returns `mc`.
	pub fn get_message_count(&self) -> u128 {
		self.mc
	}

	/// Sets the value of the local ephemeral keypair as the parameter `e`.
	pub fn set_ephemeral_keypair(&mut self, e: Keypair) {
		self.hs.set_ephemeral_keypair(e);
	}
	
	/// Returns a `Option<PublicKey>` object that contains the remote party's static `PublicKey`.
	/// Note that this function returns `None` before a handshake is successfuly performed and
	/// the session is in transport mode.
	pub fn get_remote_static_public_key(&self) -> Option<PublicKey> {
		if self.is_transport {
			return Some(self.hs.get_remote_static_public_key());
		}
		None
	}

/* $NOISE2RS_P$ */
}
