/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */

#![allow(non_snake_case, non_upper_case_globals)]

pub const DHLEN: usize = 32_usize;
pub(crate) const HASHLEN: usize = 32_usize;
pub(crate) const BLOCKLEN: usize = 64_usize;
pub(crate) const EMPTY_HASH: [u8; DHLEN] = [0_u8; HASHLEN];
pub(crate) const EMPTY_KEY: [u8; DHLEN] = [0_u8; DHLEN];
pub const MAC_LENGTH: usize = 16_usize;
pub(crate) const MAX_MESSAGE: usize = 0xFFFF;
pub(crate) const MAX_NONCE: u64 = u64::max_value();
pub(crate) const NONCE_LENGTH: usize = 12_usize;
pub(crate) const ZEROLEN: [u8; 0] = [0_u8; 0];