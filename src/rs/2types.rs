/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

pub struct Keypair {
	sk: curve25519::SecretKey,
	pub pk: curve25519::PublicKey,
}

impl Keypair {
	pub fn new_k(k: [u8; 32]) -> Keypair {
		let test_sk = k;
		let test_pk = generate_public_key(&test_sk);
		Keypair {
			pk: curve25519::PublicKey(test_pk),
			sk: curve25519::SecretKey(test_sk),
		}
	}
	pub fn new_empty() -> Keypair {
		Keypair {
			pk: curve25519::PublicKey(generate_public_key(&EMPTY_KEY)),
			sk: curve25519::SecretKey(EMPTY_KEY),
		}
	}
}

pub struct MessageBuffer {
	pub ne: [u8; DHLEN],
	pub ns: Vec<u8>,
	pub ciphertext: Vec<u8>,
}

struct CipherState {
	k: [u8; DHLEN],
	n: u64,
}

struct SymmetricState {
	cs: CipherState,
	ck: [u8; HASHLEN],
	h: [u8; HASHLEN],
}

struct HandshakeState {
	ss: SymmetricState,
	s: Keypair,
	e: Keypair,
	rs: [u8; DHLEN],
	re: [u8; DHLEN],
	psk: [u8; DHLEN],
}

pub struct NoiseSession {
	hs: HandshakeState,
	h: [u8; DHLEN],
	cs1: CipherState,
	cs2: CipherState,
	mc: u32,
	i: bool,
}
