/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

use crate::consts::{DHLEN, EMPTY_KEY, HASHLEN, MAX_MESSAGE, MAX_NONCE, PSK_LENGTH};
use hacl_star::curve25519;
use rand;
use zeroize::Zeroize;

fn decode_str_32(s: &str) -> [u8; DHLEN] {
	if let Ok(x) = hex::decode(s) {
		if x.len() == DHLEN {
			let mut temp: [u8; DHLEN] = [0u8; DHLEN];
			temp.copy_from_slice(&x[..]);
			temp
		} else {
			panic!("Invalid input length; decode_32");
		}
	} else {
		panic!("Invalid input length; decode_32");
	}
}

fn decode_str(s: &str) -> Vec<u8> {
	if let Ok(x) = hex::decode(s) {
		x
	} else {
		panic!("{:X?}", hex::decode(s).err());
	}
}

#[derive(Clone)]
pub(crate) struct Hash {
	h: [u8; HASHLEN],
}
impl Hash {
	pub fn clear(&mut self) {
		self.h.zeroize();
	}
	pub fn new(hash: [u8; HASHLEN]) -> Hash {
		Hash { h: hash }
	}
	pub fn as_bytes(&self) -> &[u8; DHLEN] {
		&self.h
	}
	pub fn empty() -> Hash {
		Hash::new([0u8; HASHLEN])
	}
}

#[derive(Clone)]
pub struct Key {
	k: [u8; DHLEN],
}
impl Key {
	pub(crate) fn clear(&mut self) {
		self.k.zeroize();
	}
	pub fn new() -> Key {
		Key::from_bytes(EMPTY_KEY)
	}
	pub fn from_bytes(key: [u8; 32]) -> Key {
		Key { k: key }
	}
	pub fn from_str(key: &str) -> Key {
		Key::from_bytes(decode_str_32(key))
	}
	pub(crate) fn as_bytes(&self) -> &[u8; DHLEN] {
		&self.k
	}
	pub fn is_empty(&self) -> bool {
		crypto::util::fixed_time_eq(&self.k[..], &EMPTY_KEY)
	}
	pub fn generate_public_key(private_key: &[u8; DHLEN]) -> PublicKey {
		let mut output: [u8; DHLEN] = EMPTY_KEY;
		output.copy_from_slice(private_key);
		let output = curve25519::SecretKey(output).get_public();
		PublicKey { k: output.0 }
	}
}

#[derive(Clone)]
pub struct Psk {
	psk: [u8; DHLEN],
}
impl Psk {
	pub fn new() -> Psk {
		Psk::from_bytes(EMPTY_KEY)
	}
	pub(crate) fn clear(&mut self) {
		self.psk.zeroize();
	}
	pub fn from_bytes(k: [u8; DHLEN]) -> Psk {
		Psk { psk: k }
	}
	pub fn from_str(k: &str) -> Psk {
		let psk = decode_str_32(k);
		if psk.len() != PSK_LENGTH {
			panic!("Invalid PSK Length");
		}
		Psk::from_bytes(psk)
	}
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.psk
	}
	pub fn is_empty(&self) -> bool {
		crypto::util::fixed_time_eq(&self.psk[..], &EMPTY_KEY)
	}
}

#[derive(Clone)]
pub struct PrivateKey {
	k: [u8; DHLEN],
}
impl PrivateKey {
	pub(crate) fn clear(&mut self) {
		self.k.zeroize();
	}
	pub fn empty() -> PrivateKey {
		PrivateKey { k: EMPTY_KEY }
	}
	pub fn from_bytes(k: [u8; 32]) -> PrivateKey {
		PrivateKey::from_hacl_secret_key(curve25519::SecretKey(k))
	}
	pub fn from_hacl_secret_key(hacl_secret: curve25519::SecretKey) -> PrivateKey {
		PrivateKey { k: hacl_secret.0 }
	}
	pub fn from_str(key: &str) -> PrivateKey {
		PrivateKey::from_hacl_secret_key(curve25519::SecretKey(decode_str_32(key)))
	}
	pub(crate) fn as_bytes(&self) -> &[u8; DHLEN] {
		&self.k
	}
	pub fn is_empty(&self) -> bool {
		crypto::util::fixed_time_eq(&self.k[..], &EMPTY_KEY)
	}
	pub fn generate_public_key(&self) -> PublicKey {
		if self.is_empty() {
			panic!("Private Key is EMPTY_KEY");
		}
		PublicKey {
			k: curve25519::SecretKey(self.k).get_public().0,
		}
	}
}

#[derive(Copy, Clone)]
pub struct PublicKey {
	k: [u8; DHLEN],
}
impl PublicKey {
	pub fn new() -> PublicKey {
		PublicKey { k: EMPTY_KEY }
	}
	pub fn from_bytes(k: [u8; 32]) -> PublicKey {
		PublicKey { k: k }
	}
	pub(crate) fn clear(&mut self) {
		self.k.zeroize();
	}
	pub fn from_str(key: &str) -> PublicKey {
		PublicKey::from_hacl_public_key(curve25519::PublicKey(decode_str_32(key)))
	}
	pub fn from_hacl_public_key(hacl_public: curve25519::PublicKey) -> PublicKey {
		PublicKey { k: hacl_public.0 }
	}
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.k
	}
	pub fn is_empty(&self) -> bool {
		crypto::util::fixed_time_eq(&self.k[..], &EMPTY_KEY)
	}
}

#[derive(Copy, Clone)]
pub(crate) struct Nonce {
	n: u64,
}
impl Nonce {
	pub(crate) fn new() -> Nonce {
		Nonce { n: 0u64 }
	}
	pub(crate) fn increment(&mut self) {
		self.n += 1;
	}
	pub(crate) fn get_value(self) -> u64 {
		if self.n == MAX_NONCE {
			panic!("MAX NONCE");
		}
		self.n
	}
}

#[derive(Clone)]
pub struct MessageBuffer {
	pub ne: [u8; DHLEN],
	pub ns: Vec<u8>,
	pub ciphertext: Vec<u8>,
}

#[derive(Clone)]
pub struct Message {
	payload: Vec<u8>,
}

impl Message {
	pub fn from_vec(m: Vec<u8>) -> Message {
		if m.len() > MAX_MESSAGE {
			panic!("Message > {} bytes", MAX_MESSAGE);
		}
		Message { payload: m }
	}
	pub fn from_str(m: &str) -> Message {
		if m.len() > MAX_MESSAGE {
			panic!("Message > {} bytes", MAX_MESSAGE);
		}
		Message::from_vec(decode_str(m))
	}
	pub fn as_bytes(&self) -> &Vec<u8> {
		&self.payload
	}
	pub fn len(&self) -> usize {
		self.payload.len()
	}
}

#[derive(Clone)]
pub struct Keypair {
	private_key: PrivateKey,
	public_key: PublicKey,
}

impl Keypair {
	pub fn clear(&mut self) {
		self.private_key.clear();
		self.public_key.clear();
	}
	pub fn new_empty() -> Keypair {
		Keypair {
			private_key: PrivateKey::empty(),
			public_key: PublicKey::new(),
		}
	}
	pub fn new() -> Keypair {
		let hacl_keypair: (curve25519::SecretKey, curve25519::PublicKey) =
			curve25519::keypair(rand::thread_rng());
		Keypair {
			private_key: PrivateKey::from_hacl_secret_key(hacl_keypair.0),
			public_key: PublicKey::from_hacl_public_key(hacl_keypair.1),
		}
	}
	pub(crate) fn dh(&self, public_key: &[u8; DHLEN]) -> [u8; DHLEN] {
		let mut output: [u8; DHLEN] = EMPTY_KEY;
		curve25519::scalarmult(&mut output, &self.private_key.as_bytes(), public_key);
		output
	}

	pub fn is_empty(&self) -> bool {
		self.private_key.is_empty()
	}

	pub fn from_key(k: PrivateKey) -> Keypair {
		let public_key: PublicKey = k.generate_public_key();
		Keypair {
			private_key: k,
			public_key: public_key,
		}
	}
	pub fn from_private_key(k: PrivateKey) -> Keypair {
		Keypair::from_key(k)
	}
	pub fn get_public_key(&self) -> PublicKey {
		self.public_key
	}
}
