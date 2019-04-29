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
	pub(crate) fn clear(&mut self) {
		self.h.zeroize();
	}
	pub(crate) fn from_bytes(hash: [u8; HASHLEN]) -> Hash {
		Hash { h: hash }
	}
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.h
	}
	pub(crate) fn new() -> Hash {
		Hash::from_bytes([0u8; HASHLEN])
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
	/// Instanciates a new empty `Key`.
	pub fn new() -> Key {
		Key::from_bytes(EMPTY_KEY)
	}
	/// Instanciates a new `Key` from an array of `DHLEN` bytes.
	pub fn from_bytes(key: [u8; DHLEN]) -> Key {
		Key { k: key }
	}
	/// Instanciates a new `Key` from a string of hexadecimal values.
	/// # Example
	///
	/// ```
	/// let pk = Key::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// println!("{:?}", pk.as_bytes());
	/// ```
	pub fn from_str(key: &str) -> Key {
		Key::from_bytes(decode_str_32(key))
	}
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.k
	}
	/// Checks whether a `Key` object is empty or not.
	/// # Example
	///
	/// ```
	/// let empty_key1 = Key::from_str("000000000000000000000000000000000000000000000000000000000000000000");
	/// let empty_key2 = Key::new();
	/// let k = Key::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// assert!(empty_key1.is_empty());
	/// assert!(empty_key2.is_empty());
	/// assert!(!k.is_empty());
	/// ```
	pub fn is_empty(&self) -> bool {
		crypto::util::fixed_time_eq(&self.k[..], &EMPTY_KEY)
	}
	/// Derives a `PublicKey` from the `Key` and returns it.
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
	/// Instanciates a new empty `Psk`.
	pub fn new() -> Psk {
		Psk::from_bytes(EMPTY_KEY)
	}
	pub(crate) fn clear(&mut self) {
		self.psk.zeroize();
	}
	/// Instanciates a new `Psk` from an array of `DHLEN` bytes.
	pub fn from_bytes(k: [u8; DHLEN]) -> Psk {
		Psk { psk: k }
	}
	/// Instanciates a new `Psk` from a string of hexadecimal values.
	/// # Example
	///
	/// ```
	/// let pk = Key::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// println!("{:?}", pk.as_bytes());
	/// ```
	pub fn from_str(k: &str) -> Psk {
		let psk = decode_str_32(k);
		if psk.len() != PSK_LENGTH {
			panic!("Invalid PSK Length");
		}
		Psk::from_bytes(psk)
	}
	#[allow(dead_code)]
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.psk
	}
	/// Checks whether a `Psk` object is empty or not.
	/// # Example
	///
	/// ```
	/// let empty_key1 = Psk::from_str("000000000000000000000000000000000000000000000000000000000000000000");
	/// let empty_key2 = Psk::new();
	/// let k = Key::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// assert!(empty_key1.is_empty());
	/// assert!(empty_key2.is_empty());
	/// assert!(!k.is_empty());
	/// ```
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
	/// Instanciates a new empty `PrivateKey`.
	pub fn empty() -> PrivateKey {
		PrivateKey { k: EMPTY_KEY }
	}
	/// Instanciates a new `PrivateKey` from an array of `DHLEN` bytes.
	pub fn from_bytes(k: [u8; DHLEN]) -> PrivateKey {
		PrivateKey::from_hacl_secret_key(curve25519::SecretKey(k))
	}
	pub(crate) fn from_hacl_secret_key(hacl_secret: curve25519::SecretKey) -> PrivateKey {
		PrivateKey { k: hacl_secret.0 }
	}
	/// Instanciates a new `PrivateKey` from a string of hexadecimal values.
	/// # Example
	///
	/// ```
	/// let pk = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// println!("{:?}", pk.as_bytes());
	/// ```
	pub fn from_str(key: &str) -> PrivateKey {
		PrivateKey::from_hacl_secret_key(curve25519::SecretKey(decode_str_32(key)))
	}
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.k
	}
	/// Checks whether a `PrivateKey` object is empty or not.
	/// # Example
	///
	/// ```
	/// let empty_key1 = PrivateKey::from_str("000000000000000000000000000000000000000000000000000000000000000000");
	/// let empty_key2 = PrivateKey::new();
	/// let k = PrivateKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// assert!(empty_key1.is_empty());
	/// assert!(empty_key2.is_empty());
	/// assert!(!pk.is_empty());
	/// ```
	pub fn is_empty(&self) -> bool {
		crypto::util::fixed_time_eq(&self.k[..], &EMPTY_KEY)
	}
	/// Derives a `PublicKey` from the `PrivateKey` and returns it.
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
	/// Instanciates a new empty `PublicKey`.
	pub fn empty() -> PublicKey {
		PublicKey { k: EMPTY_KEY }
	}
	/// Instanciates a new `PublicKey` from an array of `DHLEN` bytes.
	pub fn from_bytes(k: [u8; DHLEN]) -> PublicKey {
		PublicKey { k: k }
	}
	pub(crate) fn clear(&mut self) {
		self.k.zeroize();
	}
	/// Instanciates a new `PublicKey` from a string of hexadecimal values.
	/// # Example
	///
	/// ```
	/// let pk = PublicKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// println!("{:?}", pk.as_bytes());
	/// ```
	pub fn from_str(key: &str) -> PublicKey {
		PublicKey::from_hacl_public_key(curve25519::PublicKey(decode_str_32(key)))
	}
	pub(crate) fn from_hacl_public_key(hacl_public: curve25519::PublicKey) -> PublicKey {
		PublicKey { k: hacl_public.0 }
	}
	pub(crate) fn as_bytes(&self) -> [u8; DHLEN] {
		self.k
	}
	/// Checks whether a `PublicKey` object is empty or not.
	/// # Example
	///
	/// ```
	/// let empty_key1 = PublicKey::from_str("000000000000000000000000000000000000000000000000000000000000000000");
	/// let empty_key2 = PublicKey::new();
	/// let k = PublicKey::from_str("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
	///
	/// assert!(empty_key1.is_empty());
	/// assert!(empty_key2.is_empty());
	/// assert!(!pk.is_empty());
	/// ```
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
pub struct Message {
	payload: Vec<u8>,
}
impl Message {
	/// Instanciates a new `Message` from a `Vec<u8>`.
	pub fn from_vec(m: Vec<u8>) -> Message {
		if m.len() > MAX_MESSAGE {
			panic!("Message > {} bytes", MAX_MESSAGE);
		}
		Message { payload: m }
	}
	/// Instanciates a new `Message` from a `&str`.
	pub fn from_str(m: &str) -> Message {
		Message::from_vec(decode_str(m))
	}
	/// Instanciates a new `Message` from a `&[u8]`.
	pub fn from_bytes(m: &[u8]) -> Message {
		Message::from_vec(Vec::from(m))
	}
	/// View the `Message` payload as a `Vec<u8>`.
	pub fn as_bytes(&self) -> &Vec<u8> {
		&self.payload
	}
	/// Returns a `usize` value that represents the `Message` payload length in bytes.
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
	/// Instanciates a `Keypair` where the `PrivateKey` and `PublicKey` fields are filled with 0 bytes.
	pub fn new_empty() -> Keypair {
		Keypair {
			private_key: PrivateKey::empty(),
			public_key: PublicKey::empty(),
		}
	}
	/// Instanciates a `Keypair` by generating a `PrivateKey` from random values using `thread_rng()`, then deriving the corresponding `PublicKey`
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
	/// Checks if the `PrivateKey` field of a `Keypair` is empty and returns either `true` or `false` accordingly.
	pub fn is_empty(&self) -> bool {
		self.private_key.is_empty()
	}
	/// Derives a `PublicKey` from a `Key` and returns a `Keypair` containing the previous two values.
	pub fn from_key(k: PrivateKey) -> Keypair {
		let public_key: PublicKey = k.generate_public_key();
		Keypair {
			private_key: k,
			public_key: public_key,
		}
	}
	/// Derives a `PublicKey` from a `PrivateKey` and returns a `Keypair` containing the previous two values.
	pub fn from_private_key(k: PrivateKey) -> Keypair {
		Keypair::from_key(k)
	}
	/// Returns the `PublicKey` value from the `Keypair`
	pub fn get_public_key(&self) -> PublicKey {
		self.public_key
	}
}
