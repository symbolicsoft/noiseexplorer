/* ---------------------------------------------------------------- *
 * STATE MANAGEMENT                                                 *
 * ---------------------------------------------------------------- */

/* CipherState */
func initializeKey(k [32]byte) cipherstate {
	return cipherstate{k, minNonce}
}

func hasKey(cs *cipherstate) bool {
	return !isEmptyKey(cs.k)
}

func setNonce(cs *cipherstate, newNonce uint64) *cipherstate {
	cs.n = newNonce
	return cs
}

func encryptWithAd(cs *cipherstate, ad []byte, plaintext []byte) (*cipherstate, []byte, error) {
	var err error
	if cs.n == math.MaxUint64-1 {
		err = errors.New("encryptWithAd: maximum nonce size reached")
		return cs, []byte{}, err
	}
	e := encrypt(cs.k, cs.n, ad, plaintext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, e, err
}

func decryptWithAd(cs *cipherstate, ad []byte, ciphertext []byte) (*cipherstate, []byte, bool, error) {
	var err error
	if cs.n == math.MaxUint64-1 {
		err = errors.New("decryptWithAd: maximum nonce size reached")
		return cs, []byte{}, false, err
	}
	valid, ad, plaintext := decrypt(cs.k, cs.n, ad, ciphertext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, plaintext, valid, err
}

func reKey(cs *cipherstate) *cipherstate {
	e := encrypt(cs.k, math.MaxUint64, []byte{}, emptyKey[:])
	copy(cs.k[:], e)
	return cs
}

/* SymmetricState */

func initializeSymmetric(protocolName []byte) symmetricstate {
	h := hashProtocolName(protocolName)
	ck := h
	cs := initializeKey(emptyKey)
	return symmetricstate{cs, ck, h}
}

func mixKey(ss *symmetricstate, ikm [32]byte) *symmetricstate {
	ck, tempK, _ := getHkdf(ss.ck, ikm[:])
	ss.cs = initializeKey(tempK)
	ss.ck = ck
	return ss
}

func mixHash(ss *symmetricstate, data []byte) *symmetricstate {
	ss.h = getHash(ss.h[:], data)
	return ss
}

func mixKeyAndHash(ss *symmetricstate, ikm [32]byte) *symmetricstate {
	var tempH [32]byte
	var tempK [32]byte
	ss.ck, tempH, tempK = getHkdf(ss.ck, ikm[:])
	ss = mixHash(ss, tempH[:])
	ss.cs = initializeKey(tempK)
	return ss
}

func getHandshakeHash(ss *symmetricstate) [32]byte {
	return ss.h
}

func encryptAndHash(ss *symmetricstate, plaintext []byte) (*symmetricstate, []byte, error) {
	var ciphertext []byte
	var err error
	if hasKey(&ss.cs) {
		_, ciphertext, err = encryptWithAd(&ss.cs, ss.h[:], plaintext)
		if err != nil {
			return ss, []byte{}, err
		}
	} else {
		ciphertext = plaintext
	}
	ss = mixHash(ss, ciphertext)
	return ss, ciphertext, err
}

func decryptAndHash(ss *symmetricstate, ciphertext []byte) (*symmetricstate, []byte, bool, error) {
	var plaintext []byte
	var valid bool
	var err error
	if hasKey(&ss.cs) {
		_, plaintext, valid, err = decryptWithAd(&ss.cs, ss.h[:], ciphertext)
		if err != nil {
			return ss, []byte{}, false, err
		}
	} else {
		plaintext, valid = ciphertext, true
	}
	ss = mixHash(ss, ciphertext)
	return ss, plaintext, valid, err
}

func split(ss *symmetricstate) (cipherstate, cipherstate) {
	tempK1, tempK2, _ := getHkdf(ss.ck, []byte{})
	cs1 := initializeKey(tempK1)
	cs2 := initializeKey(tempK2)
	return cs1, cs2
}

/* HandshakeState */

/* $NOISE2GO_I$ */

/* $NOISE2GO_W$ */

/* $NOISE2GO_R$ */
