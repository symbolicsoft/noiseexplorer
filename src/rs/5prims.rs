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

fn ENCRYPT(k: &[u8; DHLEN], n: u64, ad: &[u8], plaintext: &[u8]) -> Vec<u8> {
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

fn DECRYPT(k: &[u8; DHLEN], n: u64, ad: &[u8], ciphertext: &[u8]) -> Option<Vec<u8>> {
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