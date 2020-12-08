/*
NN:
  -> e
  <- e, ee
  ->
  <-
*/

// Implementation Version: 1.0.2

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"hash"
	"io"
	"math"
)

/* ---------------------------------------------------------------- *
 * TYPES                                                            *
 * ---------------------------------------------------------------- */

type keypair struct {
	public_key  [32]byte
	private_key [32]byte
}

type messagebuffer struct {
	ne         [32]byte
	ns         []byte
	ciphertext []byte
}

type cipherstate struct {
	k [32]byte
	n uint32
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

/* ---------------------------------------------------------------- *
 * CONSTANTS                                                        *
 * ---------------------------------------------------------------- */

var emptyKey = [32]byte{
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

var minNonce = uint32(0)

/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

func getPublicKey(kp *keypair) [32]byte {
	return kp.public_key
}

func isEmptyKey(k [32]byte) bool {
	return subtle.ConstantTimeCompare(k[:], emptyKey[:]) == 1
}

func validatePublicKey(k []byte) bool {
	forbiddenCurveValues := [12][]byte{
		{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		{224, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 0},
		{95, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 87},
		{236, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{237, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{238, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127},
		{205, 235, 122, 124, 59, 65, 184, 174, 22, 86, 227, 250, 241, 159, 196, 106, 218, 9, 141, 235, 156, 50, 177, 253, 134, 98, 5, 22, 95, 73, 184, 128},
		{76, 156, 149, 188, 163, 80, 140, 36, 177, 208, 177, 85, 156, 131, 239, 91, 4, 68, 92, 196, 88, 28, 142, 134, 216, 34, 78, 221, 208, 159, 17, 215},
		{217, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{218, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
		{219, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 25},
	}

	for _, testValue := range forbiddenCurveValues {
		if subtle.ConstantTimeCompare(k[:], testValue[:]) == 1 {
			panic("Invalid public key")
		}
	}
	return true
}
/* ---------------------------------------------------------------- *
 * PRIMITIVES                                                       *
 * ---------------------------------------------------------------- */

func incrementNonce(n uint32) uint32 {
	return n + 1
}

func dh(private_key [32]byte, public_key [32]byte) [32]byte {
	var ss [32]byte
	curve25519.ScalarMult(&ss, &private_key, &public_key)
	return ss
}

func generateKeypair() keypair {
	var public_key [32]byte
	var private_key [32]byte
	_, _ = rand.Read(private_key[:])
	curve25519.ScalarBaseMult(&public_key, &private_key)
	if validatePublicKey(public_key[:]) {
		return keypair{public_key, private_key}
	}
	return generateKeypair()
}

func generatePublicKey(private_key [32]byte) [32]byte {
	var public_key [32]byte
	curve25519.ScalarBaseMult(&public_key, &private_key)
	return public_key
}

func encrypt(k [32]byte, n uint32, ad []byte, plaintext []byte) []byte {
	var nonce [12]byte
	var ciphertext []byte
	enc, _ := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint32(nonce[4:], n)
	ciphertext = enc.Seal(nil, nonce[:], plaintext, ad)
	return ciphertext
}

func decrypt(k [32]byte, n uint32, ad []byte, ciphertext []byte) (bool, []byte, []byte) {
	var nonce [12]byte
	var plaintext []byte
	enc, err := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint32(nonce[4:], n)
	plaintext, err = enc.Open(nil, nonce[:], ciphertext, ad)
	return (err == nil), ad, plaintext
}

func getHash(a []byte, b []byte) [32]byte {
	return blake2s.Sum256(append(a, b...))
}

func hashProtocolName(protocolName []byte) [32]byte {
	var h [32]byte
	if len(protocolName) <= 32 {
		copy(h[:], protocolName)
	} else {
		h = getHash(protocolName, []byte{})
	}
	return h
}

func blake2HkdfInterface() hash.Hash {
	h, _ := blake2s.New256([]byte{})
	return h
}

func getHkdf(ck [32]byte, ikm []byte) ([32]byte, [32]byte, [32]byte) {
	var k1 [32]byte
	var k2 [32]byte
	var k3 [32]byte
	output := hkdf.New(blake2HkdfInterface, ikm[:], ck[:], []byte{})
	io.ReadFull(output, k1[:])
	io.ReadFull(output, k2[:])
	io.ReadFull(output, k3[:])
	return k1, k2, k3
}

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

func setNonce(cs *cipherstate, newNonce uint32) *cipherstate {
	cs.n = newNonce
	return cs
}

func encryptWithAd(cs *cipherstate, ad []byte, plaintext []byte) (*cipherstate, []byte) {
	e := encrypt(cs.k, cs.n, ad, plaintext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, e
}

func decryptWithAd(cs *cipherstate, ad []byte, ciphertext []byte) (*cipherstate, []byte, bool) {
	valid, ad, plaintext := decrypt(cs.k, cs.n, ad, ciphertext)
	cs = setNonce(cs, incrementNonce(cs.n))
	return cs, plaintext, valid
}

func reKey(cs *cipherstate) *cipherstate {
	e := encrypt(cs.k, math.MaxUint32, []byte{}, emptyKey[:])
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

func encryptAndHash(ss *symmetricstate, plaintext []byte) (*symmetricstate, []byte) {
	var ciphertext []byte
	if hasKey(&ss.cs) {
		_, ciphertext = encryptWithAd(&ss.cs, ss.h[:], plaintext)
	} else {
		ciphertext = plaintext
	}
	ss = mixHash(ss, ciphertext)
	return ss, ciphertext
}

func decryptAndHash(ss *symmetricstate, ciphertext []byte) (*symmetricstate, []byte, bool) {
	var plaintext []byte
	var valid bool
	if hasKey(&ss.cs) {
		_, plaintext, valid = decryptWithAd(&ss.cs, ss.h[:], ciphertext)
	} else {
		plaintext, valid = ciphertext, true
	}
	ss = mixHash(ss, ciphertext)
	return ss, plaintext, valid
}

func split(ss *symmetricstate) (cipherstate, cipherstate) {
	tempK1, tempK2, _ := getHkdf(ss.ck, []byte{})
	cs1 := initializeKey(tempK1)
	cs2 := initializeKey(tempK2)
	return cs1, cs2
}

/* HandshakeState */

func initializeInitiator(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_NN_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	return handshakestate{ss, s, e, rs, re, psk}
}

func initializeResponder(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_NN_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	return handshakestate{ss, s, e, rs, re, psk}
}

func writeMessageA(hs *handshakestate, payload []byte) (*handshakestate, messagebuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	esk, _ := hex.DecodeString("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a")
	copy(hs.e.private_key[:], esk[:])
	hs.e.public_key = generatePublicKey(hs.e.private_key)
	ne = hs.e.public_key
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func writeMessageB(hs *handshakestate, payload []byte) ([32]byte, messagebuffer, cipherstate, cipherstate) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	esk, _ := hex.DecodeString("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b")
	copy(hs.e.private_key[:], esk[:])
	hs.e.public_key = generatePublicKey(hs.e.private_key)
	ne = hs.e.public_key
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.private_key, hs.re))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, messageBuffer, cs1, cs2
}

func writeMessageRegular(cs *cipherstate, payload []byte) (*cipherstate, messagebuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	cs, ciphertext = encryptWithAd(cs, []byte{}, payload)
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return cs, messageBuffer
}

func readMessageA(hs *handshakestate, message *messagebuffer) (*handshakestate, []byte, bool) {
	valid1 := true
	if validatePublicKey(message.ne[:]) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	return hs, plaintext, (valid1 && valid2)
}

func readMessageB(hs *handshakestate, message *messagebuffer) ([32]byte, []byte, bool, cipherstate, cipherstate) {
	valid1 := true
	if validatePublicKey(message.ne[:]) {
		hs.re = message.ne
	}
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.private_key, hs.re))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2
}

func readMessageRegular(cs *cipherstate, message *messagebuffer) (*cipherstate, []byte, bool) {
	/* No encrypted keys */
	_, plaintext, valid2 := decryptWithAd(cs, []byte{}, message.ciphertext)
	return cs, plaintext, valid2
}

/* ---------------------------------------------------------------- *
 * PROCESSES                                                        *
 * ---------------------------------------------------------------- */

func InitSession(initiator bool, prologue []byte, s keypair, rs [32]byte) noisesession {
	var session noisesession
	psk := emptyKey
	if initiator {
		session.hs = initializeInitiator(prologue, s, rs, psk)
	} else {
		session.hs = initializeResponder(prologue, s, rs, psk)
	}
	session.i = initiator
	session.mc = 0
	return session
}

func SendMessage(session *noisesession, message []byte) (*noisesession, messagebuffer) {
	var messageBuffer messagebuffer
	if session.mc == 0 {
		_, messageBuffer = writeMessageA(&session.hs, message)
	}
	if session.mc == 1 {
		session.h, messageBuffer, session.cs1, session.cs2 = writeMessageB(&session.hs, message)
		session.hs = handshakestate{}
	}
	if session.mc > 1 {
		if session.i {
			_, messageBuffer = writeMessageRegular(&session.cs1, message)
		} else {
			_, messageBuffer = writeMessageRegular(&session.cs2, message)
		}
	}
	session.mc = session.mc + 1
	return session, messageBuffer
}

func RecvMessage(session *noisesession, message *messagebuffer) (*noisesession, []byte, bool) {
	var plaintext []byte
	var valid bool
	if session.mc == 0 {
		_, plaintext, valid = readMessageA(&session.hs, message)
	}
	if session.mc == 1 {
		session.h, plaintext, valid, session.cs1, session.cs2 = readMessageB(&session.hs, message)
		session.hs = handshakestate{}
	}
	if session.mc > 1 {
		if session.i {
			_, plaintext, valid = readMessageRegular(&session.cs2, message)
		} else {
			_, plaintext, valid = readMessageRegular(&session.cs1, message)
		}
	}
	session.mc = session.mc + 1
	return session, plaintext, valid
}

func main() {
	prologue, _ := hex.DecodeString("4a6f686e2047616c74")
	var initStatic keypair
	initStaticSk := emptyKey
	copy(initStatic.private_key[:], initStaticSk[:])
	initStatic.public_key = generatePublicKey(initStatic.private_key)
	var respStatic keypair
	respStaticSk := emptyKey
	copy(respStatic.private_key[:], respStaticSk[:])
	respStatic.public_key = generatePublicKey(respStatic.private_key)
	initiatorSession := InitSession(true, prologue, initStatic, emptyKey)
	responderSession := InitSession(false, prologue, respStatic, emptyKey)
	payloadA, _ := hex.DecodeString("4c756477696720766f6e204d69736573")
	_, messageA := SendMessage(&initiatorSession, payloadA)
	_, _, validA := RecvMessage(&responderSession, &messageA)
	tA := "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573"
	payloadB, _ := hex.DecodeString("4d757272617920526f746862617264")
	_, messageB := SendMessage(&responderSession, payloadB)
	_, _, validB := RecvMessage(&initiatorSession, &messageB)
	tB := "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843ff34a6759d06e7733c83aeb5556c15bc762b664b3ba0556b1e7eaea4168bb6"
	payloadC, _ := hex.DecodeString("462e20412e20486179656b")
	_, messageC := SendMessage(&initiatorSession, payloadC)
	_, _, validC := RecvMessage(&responderSession, &messageC)
	tC := "79285da88da3535f52b07b70006c85706de7ddb1fd3dddac995b7e"
	payloadD, _ := hex.DecodeString("4361726c204d656e676572")
	_, messageD := SendMessage(&responderSession, payloadD)
	_, _, validD := RecvMessage(&initiatorSession, &messageD)
	tD := "ffdad3a7f0db4c39077f223659c5c1d107666405566ecdf4ab53bf"
	payloadE, _ := hex.DecodeString("4a65616e2d426170746973746520536179")
	_, messageE := SendMessage(&initiatorSession, payloadE)
	_, _, validE := RecvMessage(&responderSession, &messageE)
	tE := "2b9801f5084b9a7e9df57382fb4af099a63cd8ff97bc3284c4c5f28994be58ae46"
	payloadF, _ := hex.DecodeString("457567656e2042f6686d20766f6e2042617765726b")
	_, messageF := SendMessage(&responderSession, payloadF)
	_, _, validF := RecvMessage(&initiatorSession, &messageF)
	tF := "6c94a97c5de175c870fb9e8d5c50c59d20752b0695baf24e151011ee46a184a65b444e9d97"
	if validA && validB && validC && validD && validE && validF {
		println("Sanity check PASS for NN_25519_ChaChaPoly_BLAKE2s.")
	} else {
		println("Sanity check FAIL for NN_25519_ChaChaPoly_BLAKE2s.")
	}
	cA := hex.EncodeToString(messageA.ne[:]) + hex.EncodeToString(messageA.ns) + hex.EncodeToString(messageA.ciphertext)
	cB := hex.EncodeToString(messageB.ne[:]) + hex.EncodeToString(messageB.ns) + hex.EncodeToString(messageB.ciphertext)
	cC := hex.EncodeToString(messageC.ns) + hex.EncodeToString(messageC.ciphertext)
	cD := hex.EncodeToString(messageD.ns) + hex.EncodeToString(messageD.ciphertext)
	cE := hex.EncodeToString(messageE.ns) + hex.EncodeToString(messageE.ciphertext)
	cF := hex.EncodeToString(messageF.ns) + hex.EncodeToString(messageF.ciphertext)
	if tA == cA {
		println("Test A: PASS")
	} else {
		println("Test A: FAIL")
		println("Expected: ", tA)
		println("Actual:   ", cA)
	}
	if tB == cB {
		println("Test B: PASS")
	} else {
		println("Test B: FAIL")
		println("Expected: ", tB)
		println("Actual:   ", cB)
	}
	if tC == cC {
		println("Test C: PASS")
	} else {
		println("Test C: FAIL")
		println("Expected: ", tC)
		println("Actual:   ", cC)
	}
	if tD == cD {
		println("Test D: PASS")
	} else {
		println("Test D: FAIL")
		println("Expected: ", tD)
		println("Actual:   ", cD)
	}
	if tE == cE {
		println("Test E: PASS")
	} else {
		println("Test E: FAIL")
		println("Expected: ", tE)
		println("Actual:   ", cE)
	}
	if tF == cF {
		println("Test F: PASS")
	} else {
		println("Test F: FAIL")
		println("Expected: ", tF)
		println("Actual:   ", cF)
	}
}