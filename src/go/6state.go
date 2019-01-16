/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */

/* CipherState */
func initializeKey(k [32]byte) cipherstate {
	return cipherstate{k, minNonce}
}

func hasKey(cs cipherstate) bool {
	return !isEmptyKey(cs.k)
}

func setNonce(cs cipherstate, newNonce uint64) cipherstate {
	return cipherstate{cs.k, newNonce}
}

func encryptWithAd(cs cipherstate, ad []byte, plaintext []byte) (cipherstate, []byte) {
	e := encrypt(cs.k, cs.n, ad, plaintext)
	csi := setNonce(cs, incrementNonce(cs.n))
	return csi, e
}

func decryptWithAd(cs cipherstate, ad []byte, ciphertext []byte) (cipherstate, []byte, bool) {
	valid, ad, plaintext := decrypt(cs.k, cs.n, ad, ciphertext)
	csi := setNonce(cs, incrementNonce(cs.n))
	return csi, plaintext, valid
}

func reKey(cs cipherstate) cipherstate {
	var ki [32]byte
	e := encrypt(cs.k, math.MaxUint64, []byte{}, emptyKey[:])
	for i := 0; i < 32; i++ {
		ki[i] = e[i]
	}
	return cipherstate{ki, cs.n}
}

/* SymmetricState */

func initializeSymmetric(protocolName []byte) symmetricstate {
	h := hashProtocolName(protocolName)
	ck := h
	cs := initializeKey(emptyKey)
	return symmetricstate{cs, ck, h}
}

func mixKey(ss symmetricstate, ikm [32]byte) symmetricstate {
	ck, tempK, _ := getHkdf(ss.ck, ikm[:])
	csi := initializeKey(tempK)
	return symmetricstate{csi, ck, ss.h}
}

func mixHash(ss symmetricstate, data []byte) symmetricstate {
	return symmetricstate{ss.cs, ss.ck, getHash(ss.h[:], data)}
}

func mixKeyAndHash(ss symmetricstate, ikm [32]byte) symmetricstate {
	ck, tempH, tempK := getHkdf(ss.ck, ikm[:])
	ssi := mixHash(symmetricstate{ss.cs, ck, ss.h}, tempH[:])
	return symmetricstate{initializeKey(tempK), ck, ssi.h}
}

func getHandshakeHash(ss symmetricstate) [32]byte {
	return ss.h
}

func encryptAndHash(ss symmetricstate, plaintext []byte) (symmetricstate, []byte) {
	var csi cipherstate
	var ciphertext []byte
	if hasKey(ss.cs) {
		csi, ciphertext = encryptWithAd(ss.cs, ss.h[:], plaintext)
	} else {
		csi, ciphertext = ss.cs, plaintext
	}
	ssi := mixHash(symmetricstate{csi, ss.ck, ss.h}, ciphertext)
	return ssi, ciphertext
}

func decryptAndHash(ss symmetricstate, ciphertext []byte) (symmetricstate, []byte, bool) {
	var csi cipherstate
	var plaintext []byte
	var valid bool
	if hasKey(ss.cs) {
		csi, plaintext, valid = decryptWithAd(ss.cs, ss.h[:], ciphertext)
	} else {
		csi, plaintext, valid = ss.cs, ciphertext, true
	}
	ssi := mixHash(symmetricstate{csi, ss.ck, ss.h}, ciphertext)
	return ssi, plaintext, valid
}

func split(ss symmetricstate) (cipherstate, cipherstate) {
	tempK1, tempK2, _ := getHkdf(ss.ck, []byte{})
	cs1 := initializeKey(tempK1)
	cs2 := initializeKey(tempK2)
	return cs1, cs2
}

/* HandshakeState */

/* $NOISE2GO_I$ */

/* $NOISE2GO_W$ */

/* $NOISE2GO_R$ */
