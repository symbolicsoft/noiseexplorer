/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

use crate::{
    consts::HASHLEN,
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
    pub fn clear_own_cipherstate (&mut self) {
        self.cs1.clear();
    }
    pub fn clear_remote_cipherstate (&mut self) {
        self.cs2.clear();
    }
    pub fn end_session (&mut self) {
        self.hs.clear();
        self.clear_own_cipherstate();
        self.clear_remote_cipherstate();
        self.cs2.clear();
        self.mc = 0;
        self.h = Hash::new();
    }
    pub fn get_handshake_hash(&self) -> [u8; HASHLEN] {
        self.h.as_bytes()
    }
	pub fn set_ephemeral_keypair(&mut self, e: Keypair) {
        self.hs.set_ephemeral_keypair(e);
    }
/* $NOISE2RS_P$ */
}
