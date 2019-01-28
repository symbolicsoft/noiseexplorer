/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

type keypair struct {
	pk [32]byte
	sk [32]byte
}

type messagebuffer struct {
	ne         [32]byte
	ns         []byte
	ciphertext []byte
}

type cipherstate struct {
	k [32]byte
	n uint64
}

type symmetricstate struct {
	cs cipherstate
	ck [32]byte
	h  [32]byte
}

type handshakestate struct {
	ss  symmetricstate
	s   keypair
	e   keypair
	rs  [32]byte
	re  [32]byte
	psk [32]byte
}

type noisesession struct {
	hs  handshakestate
	h   [32]byte
	cs1 cipherstate
	cs2 cipherstate
	mc  uint64
	i   bool
}
