/*
KKpsk2:
  -> s
  <- s
  ...
  -> e, es, ss
  <- e, ee, se, psk
  ->
  <-
*/

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

#![allow(non_snake_case, non_upper_case_globals)]

use byteorder::{ByteOrder, LittleEndian};
use crypto::blake2s::Blake2s;
use crypto::digest::Digest;
use hacl_star::chacha20poly1305;
use hacl_star::curve25519;
use hex;

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
			pk: curve25519::PublicKey(EMPTY_KEY),
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
	// i: bool,
}

pub struct NoiseSession {
	hs: HandshakeState,
	h: [u8; DHLEN],
	cs1: CipherState,
	cs2: CipherState,
	mc: u32,
	i: bool,
}

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

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

macro_rules! copy_slices {
	($inslice:expr, $outslice:expr) => {
		$outslice[..$inslice.len()].clone_from_slice(&$inslice[..])
	};
}

fn from_slice_HASHLEN(bytes: &[u8]) -> [u8; HASHLEN] {
	let mut array = [0u8; HASHLEN];
	let bytes = &bytes[..array.len()];
	array.copy_from_slice(bytes);
	array
}

// TEST ONLY
pub fn decode_str_32(s: &str) -> [u8; 32] {
	if let Ok(x) = hex::decode(s) {
		if x.len() == 32 {
			let mut temp: [u8; 32] = [0u8; 32];
			temp.copy_from_slice(&x[..]);
			temp
		} else {
			panic!("Invalid input length; decode_32");
		}
	} else {
		panic!("Invalid input length; decode_32");
	}
}

// TEST ONLY
fn decode_str(s: &str) -> Vec<u8> {
    if let Ok(x) = hex::decode(s) {
        x
    } else {
        panic!("{:X?}", hex::decode(s).err());
    }
}
/* ---------------------------------------------------------------- *
 * PRIMITIVES                                                       *
 * ---------------------------------------------------------------- */

fn increment_nonce(n: u64) -> u64 {
	n + 1
}

fn DH(kp: &Keypair, pk: &[u8; DHLEN]) -> [u8; DHLEN] {
	let mut output: [u8; DHLEN] = EMPTY_KEY;
	curve25519::scalarmult(&mut output, &kp.sk.0, pk);
	output
}

fn GENERATE_KEYPAIR() -> Keypair {
	let a: (curve25519::SecretKey, curve25519::PublicKey) = curve25519::keypair(rand::thread_rng());
	Keypair { sk: a.0, pk: a.1 }
}

fn generate_public_key(sk: &[u8; DHLEN]) -> [u8; DHLEN] {
	let mut output: [u8; DHLEN] = EMPTY_KEY;
	output.copy_from_slice(sk);
	let output = curve25519::SecretKey(output).get_public();
	output.0
}

pub fn ENCRYPT(k: &[u8; DHLEN], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
	let mut mac: [u8; MAC_LENGTH] = [0u8; MAC_LENGTH];
	let mut in_out = plaintext.to_owned();
	let mut nonce: [u8; NONCE_LENGTH] = [0u8; NONCE_LENGTH];
	LittleEndian::write_u64(&mut nonce[4..], n);
	chacha20poly1305::key(&k)
		.nonce(&nonce)
		.encrypt(&ad, &mut in_out[..], &mut mac);
	let mut ciphertext: Vec<u8> = in_out;
	let mut tag: Vec<u8> = Vec::from(&mac[..]);
	ciphertext.append(&mut tag);
	ciphertext
}

pub fn DECRYPT(k: &[u8; DHLEN], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
	let temp = Vec::from(ciphertext);
	// Might panic here (if mac has illegal length)
	let (x, y) = temp.split_at(temp.len() - MAC_LENGTH);
	let mut in_out = x.to_owned();
	let mut mac: [u8; MAC_LENGTH] = [0u8; MAC_LENGTH];
	mac.copy_from_slice(y);
	let mut nonce: [u8; NONCE_LENGTH] = [0u8; NONCE_LENGTH];
	LittleEndian::write_u64(&mut nonce[4..], n);
	let decryption_status =
		chacha20poly1305::key(&k)
			.nonce(&nonce)
			.decrypt(&ad, &mut in_out[..], &mac);
	if decryption_status {
		Some(in_out)
	} else {
		None
	}
}

fn HASH(data: &[u8]) -> Vec<u8> {
	let mut blake2s: Blake2s = Blake2s::new(HASHLEN);
	blake2s.input(&data[..]);
	let digest_res: &mut [u8] = &mut [0u8; HASHLEN];
	blake2s.result(digest_res);
	blake2s.reset();
	Vec::from(digest_res)
}

fn hmac(key: &[u8], data: &[u8], out: &mut [u8]) {
	let mut blake2s: Blake2s = Blake2s::new(HASHLEN);
	let mut ipad = [0x36u8; BLOCKLEN];
	let mut opad = [0x5cu8; BLOCKLEN];
	for count in 0..key.len() {
		ipad[count] ^= key[count];
		opad[count] ^= key[count];
	}
	blake2s.reset();
	blake2s.input(&ipad[..BLOCKLEN]);
	blake2s.input(data);
	let mut inner_output = [0u8; HASHLEN];
	blake2s.result(&mut inner_output);
	blake2s.reset();
	blake2s.input(&opad[..BLOCKLEN]);
	blake2s.input(&inner_output[..HASHLEN]);
	blake2s.result(out);
}

fn HKDF(
	chaining_key: &[u8],
	input_key_material: &[u8],
	outputs: usize,
	out1: &mut [u8],
	out2: &mut [u8],
	out3: &mut [u8],
) {
	let mut temp_key = [0u8; HASHLEN];
	hmac(chaining_key, input_key_material, &mut temp_key);
	hmac(&temp_key, &[1u8], out1);
	if outputs == 1 {
		return;
	}

	let mut in2 = [0u8; HASHLEN + 1];
	copy_slices!(&out1[0..HASHLEN], &mut in2);
	in2[HASHLEN] = 2;
	hmac(&temp_key, &in2[..=HASHLEN], out2);
	if outputs == 2 {
		return;
	}

	let mut in3 = [0u8; HASHLEN + 1];
	copy_slices!(&out2[0..HASHLEN], &mut in3);
	in3[HASHLEN] = 3;
	hmac(&temp_key, &in3[..=HASHLEN], out3);
}
/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */

/* CipherState */

impl CipherState {
	fn InitializeKey(k: &[u8; DHLEN]) -> CipherState {
		let mut temp: [u8; DHLEN] = [0u8; DHLEN];
		temp.copy_from_slice(k);
		CipherState {
			k: temp,
			n: MIN_NONCE,
		}
	}
	fn HasKey(&self) -> bool {
		!crypto::util::fixed_time_eq(&self.k[..], &EMPTY_KEY[..])
	}
	fn SetNonce(&mut self, new_nonce: u64) {
		self.n = new_nonce;
	}

	fn EncryptWithAd(&mut self, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
		if !self.HasKey() {
			Vec::from(plaintext)
		} else {
			let ciphertext: Vec<u8> = ENCRYPT(&self.k, self.n, ad, plaintext);
			self.SetNonce(increment_nonce(self.n));
			ciphertext
		}
	}

	fn DecryptWithAd(&mut self, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
		if !self.HasKey() {
			Some(Vec::from(ciphertext))
		} else if let Some(plaintext) = DECRYPT(&self.k, self.n, ad, ciphertext) {
			self.SetNonce(increment_nonce(self.n));
			Some(plaintext)
		} else {
			println!("Unsuccessful Decryption, problem with ad, nonce not incremented\n\nDECRYPT({:X?}, {:X?}, {:X?}, {:X?})", &self.k, &self.n, ad, ciphertext);
			None
		}
	}

	fn Rekey(&mut self) {
		let mut in_out = EMPTY_KEY;
		chacha20poly1305::key(&self.k)
			.nonce(&[0xFFu8; NONCE_LENGTH])
			.encrypt(&zerolen[..], &mut in_out[..], &mut [0u8; 16]);
		self.k = in_out;
	}

	fn WriteMessageRegular(&mut self, payload: &[u8]) -> MessageBuffer {
		MessageBuffer {
			ne: EMPTY_KEY,
			ns: Vec::new(),
			ciphertext: self.EncryptWithAd(&zerolen[..], payload),
		}
	}

	fn ReadMessageRegular(&mut self, message: &MessageBuffer) -> Option<Vec<u8>> {
		self.DecryptWithAd(&zerolen[..], &message.ciphertext)
	}
}

/* SymmetricState */

impl SymmetricState {
	fn InitializeSymmetric(protocol_name: &[u8]) -> SymmetricState {
		let mut h: [u8; DHLEN] = [0u8; DHLEN];
		match protocol_name.len() {
			0..=31 => {
				let mut temp = Vec::from(protocol_name);
				while temp.len() != HASHLEN {
					temp.push(0u8);
				}
				h.copy_from_slice(&temp[..]);
			}
			32 => h.copy_from_slice(protocol_name),
			_ => h = from_slice_HASHLEN(&HASH(protocol_name)),
		}
		let ck: [u8; DHLEN] = h;
		let cs: CipherState = CipherState::InitializeKey(&EMPTY_KEY);
		SymmetricState { cs, ck, h }
	}

	// panics if HKDF fails (slices of unequal length)
	fn MixKey(&mut self, input_key_material: &[u8]) {
		let mut out0: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		let mut out1: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		let mut out2: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		HKDF(
			&self.ck[..],
			input_key_material,
			2,
			&mut out0[..],
			&mut out1[..],
			&mut out2[..],
		);
		self.ck = from_slice_HASHLEN(&out0[..]);
		let mut temp_k: [u8; 32] = [0u8; 32];
		temp_k.copy_from_slice(&out1[..32]);
		self.cs = CipherState::InitializeKey(&temp_k);
	}

	fn MixHash(&mut self, data: &[u8]) {
		let mut temp: Vec<u8> = Vec::from(&self.h[..]);
		temp.extend(data);
		self.h = from_slice_HASHLEN(&HASH(&temp)[..]);
	}

	// panics if HKDF fails (slices of unequal length)
	fn MixKeyAndHash(&mut self, input_key_material: &[u8]) {
		let mut out0: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		let mut out1: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		let mut out2: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		HKDF(
			&self.ck[..],
			input_key_material,
			3,
			&mut out0[..],
			&mut out1[..],
			&mut out2[..],
		);
		self.ck = from_slice_HASHLEN(&out0[..]);
		let temp_h: [u8; HASHLEN] = from_slice_HASHLEN(&out1[..]);
		let mut temp_k: [u8; HASHLEN] = from_slice_HASHLEN(&out2[..]);
		self.MixHash(&temp_h[..]);
		temp_k.copy_from_slice(&out2[..32]);
		self.cs = CipherState::InitializeKey(&temp_k);
	}

	fn GetHandshakeHash(&self) -> [u8; HASHLEN] {
		let mut temp: [u8; HASHLEN] = [0u8; HASHLEN];
		temp.copy_from_slice(&self.h[..HASHLEN]);
		temp
	}

	fn EncryptAndHash(&mut self, plaintext: &[u8]) -> Option<Vec<u8>> {
		let ciphertext: Vec<u8> = self.cs.EncryptWithAd(&self.h, plaintext);
		self.MixHash(&ciphertext);
		Some(ciphertext)
	}

	// panics if ad is invalid
	fn DecryptAndHash(&mut self, ciphertext: &[u8]) -> Option<Vec<u8>> {
		if let Some(plaintext) = self.cs.DecryptWithAd(&self.h[..], &ciphertext) {
			self.MixHash(ciphertext);
			return Some(plaintext);
		} else {
			panic!("Invalid ad");
		}
	}

	//This is very messy
	//What would happen if HASHLEN != DHLEN??
	fn Split(&self) -> (CipherState, CipherState) {
		let mut out0: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		let mut out1: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		let mut out2: Vec<u8> = Vec::from(&EMPTY_KEY[..]);
		HKDF(
			&self.ck[..],
			&zerolen[..],
			2,
			&mut out0[..],
			&mut out1[..],
			&mut out2[..],
		);
		let mut temp_k1: [u8; HASHLEN] = [0u8; HASHLEN];
		let mut temp_k2: [u8; HASHLEN] = [0u8; HASHLEN];
		temp_k1.copy_from_slice(&out0[..32]);
		temp_k2.copy_from_slice(&out1[..32]);
		let c1: CipherState = CipherState::InitializeKey(&from_slice_HASHLEN(&temp_k1[..]));
		let c2: CipherState = CipherState::InitializeKey(&from_slice_HASHLEN(&temp_k2[..]));
		(c1, c2)
	}
}

/* HandshakeState */
impl HandshakeState {
fn InitializeInitiator(prologue: &[u8], s: Keypair, rs: [u8; DHLEN], psk: [u8; PSK_LENGTH]) -> HandshakeState {
	let protocol_name = b"Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
	let mut ss: SymmetricState = SymmetricState::InitializeSymmetric(&protocol_name[..]);
	ss.MixHash(prologue);
	ss.MixHash(&s.pk.0[..]);
	ss.MixHash(&rs[..]);
	HandshakeState{ss, s, e: Keypair::new_empty(), rs, re: EMPTY_KEY, psk}
}

fn InitializeResponder(prologue: &[u8], s: Keypair, rs: [u8; DHLEN], psk: [u8; PSK_LENGTH]) -> HandshakeState {
	let protocol_name = b"Noise_KKpsk2_25519_ChaChaPoly_BLAKE2s";
	let mut ss: SymmetricState = SymmetricState::InitializeSymmetric(&protocol_name[..]);
	ss.MixHash(prologue);
	ss.MixHash(&rs[..]);
	ss.MixHash(&s.pk.0[..]);
	HandshakeState{ss, s, e: Keypair::new_empty(), rs, re: EMPTY_KEY, psk}
}

fn WriteMessageA(&mut self, payload: &[u8]) -> (MessageBuffer) {
	let test_sk = decode_str_32("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
	let test_pk = generate_public_key(&test_sk);
	self.e = Keypair {
	pk: curve25519::PublicKey(test_pk),
	sk: curve25519::SecretKey(test_sk),
};
	let ne = self.e.pk.0;
	let ns: Vec<u8> = Vec::from(&zerolen[..]);
	self.ss.MixHash(&ne[..]);
	self.ss.MixKey(&self.e.pk.0);
	self.ss.MixKey(&DH(&self.e, &self.rs));
	self.ss.MixKey(&DH(&self.s, &self.rs));
	let mut ciphertext: Vec<u8> = Vec::new();
	if let Some(x) = self.ss.EncryptAndHash(payload) {
		ciphertext.clone_from(&x);
	}
	MessageBuffer { ne, ns, ciphertext }
}

fn WriteMessageB(&mut self, payload: &[u8]) -> (([u8; 32], MessageBuffer, CipherState, CipherState)) {
	let test_sk = decode_str_32("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
	let test_pk = generate_public_key(&test_sk);
	self.e = Keypair {
	pk: curve25519::PublicKey(test_pk),
	sk: curve25519::SecretKey(test_sk),
};
	let ne = self.e.pk.0;
	let ns: Vec<u8> = Vec::from(&zerolen[..]);
	self.ss.MixHash(&ne[..]);
	self.ss.MixKey(&self.e.pk.0);
	self.ss.MixKey(&DH(&self.e, &self.re));
	self.ss.MixKey(&DH(&self.e, &self.rs));
	self.ss.MixKeyAndHash(&self.psk);
	let mut ciphertext: Vec<u8> = Vec::new();
	if let Some(x) = self.ss.EncryptAndHash(payload) {
		ciphertext.clone_from(&x);
	}
	let (cs1, cs2) = self.ss.Split();
	let messagebuffer: MessageBuffer = MessageBuffer { ne, ns, ciphertext };
	(self.ss.h, messagebuffer, cs1, cs2)
}



fn ReadMessageA(&mut self, message: &mut MessageBuffer) -> (Option<Vec<u8>>) {
	self.re.copy_from_slice(&message.ne[..]);
	self.ss.MixHash(&self.re[..DHLEN]);
	self.ss.MixKey(&self.re);
	self.ss.MixKey(&DH(&self.s, &self.re));
	self.ss.MixKey(&DH(&self.s, &self.rs));
	if let Some(plaintext) = self.ss.DecryptAndHash(&message.ciphertext) {
		return Some(plaintext);
	}
	None
}

fn ReadMessageB(&mut self, message: &mut MessageBuffer) -> (Option<([u8; 32], Vec<u8>, CipherState, CipherState)>) {
	self.re.copy_from_slice(&message.ne[..]);
	self.ss.MixHash(&self.re[..DHLEN]);
	self.ss.MixKey(&self.re);
	self.ss.MixKey(&DH(&self.e, &self.re));
	self.ss.MixKey(&DH(&self.s, &self.re));
	self.ss.MixKeyAndHash(&self.psk);
	if let Some(plaintext) = self.ss.DecryptAndHash(&message.ciphertext) {
		let (cs1, cs2) = self.ss.Split();
		return Some((self.ss.h, plaintext, cs1, cs2));
	}
	None
}


}


/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

impl NoiseSession {
	pub fn InitSession(initiator: bool, prologue: &[u8], s: Keypair, rs: [u8; DHLEN], psk: [u8; PSK_LENGTH]) -> NoiseSession {
		if initiator {
			NoiseSession{
				hs: HandshakeState::InitializeInitiator(prologue, s, rs, psk),
				mc: 0,
				i: initiator,
				cs1: CipherState::InitializeKey(&EMPTY_KEY),
				cs2: CipherState::InitializeKey(&EMPTY_KEY),
				h: [0u8; 32],
			}
		} else {
			NoiseSession {
				hs: HandshakeState::InitializeResponder(prologue, s, rs, psk),
				mc: 0,
				i: initiator,
				cs1: CipherState::InitializeKey(&EMPTY_KEY),
				cs2: CipherState::InitializeKey(&EMPTY_KEY),
				h: [0u8; 32],
			}
		}
	}
	
	pub fn SendMessage(&mut self, message: &[u8]) -> MessageBuffer {
		if self.cs1.n < MAX_NONCE && self.cs2.n < MAX_NONCE
		&& self.hs.ss.cs.n < MAX_NONCE && message.len() < 65535 {
			let mut buffer: MessageBuffer = MessageBuffer {
				ne: EMPTY_KEY,
				ns: Vec::from(&zerolen[..]),
				ciphertext: Vec::from(&zerolen[..]),
			};
			if self.mc == 0 {
				buffer = self.hs.WriteMessageA(message);
			}
			if self.mc == 1 {
				let temp = self.hs.WriteMessageB(message);
				self.h = temp.0;
				buffer = temp.1;
				self.cs1 = temp.2;
				self.cs2 = temp.3;
				// Drop hs here
				self.hs = HandshakeState {
					ss: SymmetricState::InitializeSymmetric(b""),
					s: Keypair::new_empty(),
					e: Keypair::new_empty(),
					rs: EMPTY_KEY,
					re: EMPTY_KEY,
					psk: EMPTY_KEY,
				};
			}
			if self.mc > 1 {
				if self.i {
					buffer = self.cs1.WriteMessageRegular(message);
				} else {
					buffer = self.cs2.WriteMessageRegular(message);
				}
			}
			self.mc += 1;
			buffer
		} else {
			if message.len() > 65535 {
				panic!("Message too big.");
			}
			panic!("Maximum number of messages reached.");
		}
	}
	
	pub fn RecvMessage(&mut self, message: &mut MessageBuffer) -> Option<Vec<u8>> {
		if self.cs1.n < MAX_NONCE && self.cs2.n < MAX_NONCE
		&& self.hs.ss.cs.n < MAX_NONCE && message.ciphertext.len() < 65535 {
			let mut plaintext: Option<Vec<u8>> = None;
			if self.mc == 0 {
				plaintext = self.hs.ReadMessageA(message);
			}
			if self.mc == 1 {
				if let Some(temp) = self.hs.ReadMessageB(message) {
					self.h = temp.0;
					plaintext = Some(temp.1);
					self.cs1 = temp.2;
					self.cs2 = temp.3;
					// Drop hs here
					self.hs = HandshakeState {
						ss: SymmetricState::InitializeSymmetric(b""),
						s: Keypair::new_empty(),
						e: Keypair::new_empty(),
						rs: EMPTY_KEY,
						re: EMPTY_KEY,
						psk: EMPTY_KEY,
					};
				}
			}
			if self.mc > 1 {
				if self.i {
					if let Some(msg) = self.cs2.ReadMessageRegular(message) {
						plaintext = Some(msg);
					}
				} else {
					if let Some(msg) = self.cs1.ReadMessageRegular(message) {
						plaintext = Some(msg);
					}
				}
			}
			self.mc += 1;
			plaintext
		} else {
			if message.ciphertext.len() > 65535 {
				panic!("Message too big.");
			}
			panic!("Maximum number of messages reached.");
		}
	}
}

#[test]
fn KKpsk2() {
	let prologue = decode_str("4a6f686e2047616c74");
	let initStatic: Keypair = Keypair::new_k(decode_str_32("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"));
	let respStatic: Keypair = Keypair::new_k(decode_str_32("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"));
	let temp_psk1: [u8; 32] =
	decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let temp_psk2: [u8; 32] =
	decode_str_32("54686973206973206d7920417573747269616e20706572737065637469766521")
	let mut initiatorSession: NoiseSession =
	NoiseSession::InitSession(true, &prologue, initStatic, respStatic.pk.0
	let mut responderSession: NoiseSession =
	NoiseSession::InitSession(false, &prologue, respStatic, initStatic.pk.0
	let payloadA = decode_str("4c756477696720766f6e204d69736573")
	let mut messageA: MessageBuffer = initiatorSession.SendMessage(&payloadA);
	let mut validA: bool = false;
	if let Some(_x) = responderSession.RecvMessage.(&mut messageA) {
	validA = true;
}
	let tA: Vec<u8> = decode_str("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794449af0184c65dee97ea7a62c425167842186a38ba37a2240d792e0adfa651f02d");
	let payloadB = decode_str("4d757272617920526f746862617264")
	let mut messageB: MessageBuffer = responderSession.SendMessage(&payloadB);
	let mut validB: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage.(&mut messageB) {
	validB = true;
}
	let tB: Vec<u8> = decode_str("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ae4b9f90df714c75293849a0c2f7ba8080ae48c13cbf90e2c69fd23df280eb");
	let payloadC = decode_str("462e20412e20486179656b")
	let mut messageC: MessageBuffer = initiatorSession.SendMessage(&payloadC);
	let mut validC: bool = false;
	if let Some(_x) = responderSession.RecvMessage.(&mut messageC) {
	validC = true;
}
	let tC: Vec<u8> = decode_str("aaa6fbdefc0c1c2c65cb912552fe0f9647b12fce48f3d2a66d9fac");
	let payloadD = decode_str("4361726c204d656e676572")
	let mut messageD: MessageBuffer = responderSession.SendMessage(&payloadD);
	let mut validD: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage.(&mut messageD) {
	validD = true;
}
	let tD: Vec<u8> = decode_str("b872a76b5197ced1b61f9043789be7b32281aa8670d9fa166a6e95");
	let payloadE = decode_str("4a65616e2d426170746973746520536179")
	let mut messageE: MessageBuffer = initiatorSession.SendMessage(&payloadE);
	let mut validE: bool = false;
	if let Some(_x) = responderSession.RecvMessage.(&mut messageE) {
	validE = true;
}
	let tE: Vec<u8> = decode_str("9e39948aa43a63d23e775e2bf15b4e80fad721d09e8060c242eea9970cfecf4a1f");
	let payloadF = decode_str("457567656e2042f6686d20766f6e2042617765726b")
	let mut messageF: MessageBuffer = responderSession.SendMessage(&payloadF);
	let mut validF: bool = false;
	if let Some(_x) = initiatorSession.RecvMessage.(&mut messageF) {
	validF = true;
}
	let tF: Vec<u8> = decode_str("3ab72ae66cd9d291ae0ace1a71047dd55c3f36d662c250c711a06de3c6e44310c2913728dd");
	if validA && validB && validC && validD && validE && validF {
		println!("Sanity check PASS for KKpsk2_25519_ChaChaPoly_BLAKE2s.");
	} else {
		println!("Sanity check FAIL for KKpsk2_25519_ChaChaPoly_BLAKE2s.");
	}
	let mut cA: Vec<u8> = Vec::from(&messageA.ne[..]);
	cA.append(&mut messageA.ns);
	cA.append(&mut messageA.ciphertext);
	let mut cB: Vec<u8> = Vec::from(&messageB.ne[..]);
	cB.append(&mut messageB.ns);
	cB.append(&mut messageB.ciphertext);
	let mut cC: Vec<u8> = messageC.ciphertext;
	let mut cD: Vec<u8> = messageD.ciphertext;
	let mut cE: Vec<u8> = messageE.ciphertext;
	let mut cF: Vec<u8> = messageF.ciphertext;
	if tA == cA {
		println!("Test A: PASS")
	} else {
		println!("Test A: FAIL")
		println!("Expected:	", tA)
		println!("Actual:		", cA)
	}
	if tB == cB {
		println!("Test B: PASS")
	} else {
		println!("Test B: FAIL")
		println!("Expected:	", tB)
		println!("Actual:		", cB)
	}
	if tC == cC {
		println!("Test C: PASS")
	} else {
		println!("Test C: FAIL")
		println!("Expected:	", tC)
		println!("Actual:		", cC)
	}
	if tD == cD {
		println!("Test D: PASS")
	} else {
		println!("Test D: FAIL")
		println!("Expected:	", tD)
		println!("Actual:		", cD)
	}
	if tE == cE {
		println!("Test E: PASS")
	} else {
		println!("Test E: FAIL")
		println!("Expected:	", tE)
		println!("Actual:		", cE)
	}
	if tF == cF {
		println!("Test F: PASS")
	} else {
		println!("Test F: FAIL")
		println!("Expected:	", tF)
		println!("Actual:		", cF)
	}
	assert_eq!(tA, cA);
assert_eq!(tB, cB);
assert_eq!(tC, cC);
assert_eq!(tD, cD);
assert_eq!(tE, cE);
assert_eq!(tF, cF);
}
