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
/* $NOISE2RS_P$ */
}
