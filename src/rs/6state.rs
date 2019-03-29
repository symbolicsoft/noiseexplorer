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
		!is_empty(&self.k[..])
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
/* $NOISE2RS_I$ */
/* $NOISE2RS_W$ */
/* $NOISE2RS_R$ */
}