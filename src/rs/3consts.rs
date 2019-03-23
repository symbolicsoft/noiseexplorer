/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */

pub const DHLEN: usize = curve25519::SECRET_LENGTH;
const HASHLEN: usize = 32;
const BLOCKLEN: usize = 64;
pub const EMPTY_KEY: [u8; DHLEN] = [0u8; DHLEN];
const MIN_NONCE: u64 = 0u64;
const MAC_LENGTH: usize = chacha20poly1305::MAC_LENGTH;
const NONCE_LENGTH: usize = chacha20poly1305::NONCE_LENGTH;
const PSK_LENGTH: usize = 32;
const zerolen: [u8; 0] = [0u8; 0];
const MAX_NONCE: u64 = u64::max_value();
