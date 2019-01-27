/*
I1X:
  -> e, s
  <- e, ee, s, es
  -> se
  <-
  ->
*/

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
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
	i   bool
}

type noisesession struct {
	hs  handshakestate
	h   [32]byte
	cs1 cipherstate
	cs2 cipherstate
	mc  uint64
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

var minNonce = uint64(0)
/* ---------------------------------------------------------------- *
 * UTILITY FUNCTIONS                                                *
 * ---------------------------------------------------------------- */

func getPublicKey(kp *keypair) [32]byte {
	return kp.pk
}

func isEmptyKey(k [32]byte) bool {
	return subtle.ConstantTimeCompare(k[:], emptyKey[:]) == 1
}

/* ---------------------------------------------------------------- *
 * PRIMITIVES                                                       *
 * ---------------------------------------------------------------- */

func incrementNonce(n uint64) uint64 {
	return n + 1
}

func dh(sk [32]byte, pk [32]byte) [32]byte {
	var ss [32]byte
	curve25519.ScalarMult(&ss, &sk, &pk)
	return ss
}

func generateKeypair() keypair {
	var pk [32]byte
	var sk [32]byte
	_, _ = rand.Read(sk[:])
	curve25519.ScalarBaseMult(&pk, &sk)
	return keypair{pk, sk}
}

func generatePublicKey(sk [32]byte) [32]byte {
	var pk [32]byte
	curve25519.ScalarBaseMult(&pk, &sk)
	return pk
}

func encrypt(k [32]byte, n uint64, ad []byte, plaintext []byte) []byte {
	var nonce [12]byte
	var ciphertext []byte
	enc, _ := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint64(nonce[4:], n)
	ciphertext = enc.Seal(nil, nonce[:], plaintext, ad)
	return ciphertext
}

func decrypt(k [32]byte, n uint64, ad []byte, ciphertext []byte) (bool, []byte, []byte) {
	var nonce [12]byte
	var plaintext []byte
	enc, err := chacha20poly1305.New(k[:])
	binary.LittleEndian.PutUint64(nonce[4:], n)
	plaintext, err = enc.Open(nil, nonce[:], ciphertext, ad)
	return (err == nil), ad, plaintext
}

func getHash(a []byte, b []byte) [32]byte {
	return blake2s.Sum256(append(a, b...))
}

func hashProtocolName(protocolName []byte) [32]byte {
	var h [32]byte
	if len(protocolName) <= 32 {
		for i := 0; i < 32; i++ {
			if i < len(protocolName) {
				h[i] = protocolName[i]
			} else {
				h[i] = byte(0x00)
			}
		}
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

func setNonce(cs *cipherstate, newNonce uint64) *cipherstate {
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
	var ki [32]byte
	e := encrypt(cs.k, math.MaxUint64, []byte{}, emptyKey[:])
	for i := 0; i < 32; i++ {
		ki[i] = e[i]
	}
	cs.k = ki
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
	name := []byte("Noise_I1X_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	return handshakestate{ss, s, e, rs, re, psk, true}
}

func initializeResponder(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_I1X_25519_ChaChaPoly_BLAKE2s")
	ss = initializeSymmetric(name)
	mixHash(&ss, prologue)
	return handshakestate{ss, s, e, rs, re, psk, false}
}

func writeMessageA(hs *handshakestate, payload []byte) (*handshakestate, messagebuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = generateKeypair()
	ne = hs.e.pk
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	_, ns = encryptAndHash(&hs.ss, hs.s.pk[:])
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func writeMessageB(hs *handshakestate, payload []byte) (*handshakestate, messagebuffer) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	hs.e = generateKeypair()
	ne = hs.e.pk
	mixHash(&hs.ss, ne[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.sk, hs.re))
	_, ns = encryptAndHash(&hs.ss, hs.s.pk[:])
	mixKey(&hs.ss, dh(hs.s.sk, hs.re))
	_, ciphertext = encryptAndHash(&hs.ss, payload)
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func writeMessageC(hs *handshakestate, payload []byte) ([32]byte, messagebuffer, cipherstate, cipherstate) {
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	mixKey(&hs.ss, dh(hs.s.sk, hs.re))
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
	hs.re = message.ne
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	_, ns, valid1 := decryptAndHash(&hs.ss, message.ns)
	if !valid1 || len(ns) != 32 {
		return hs, []byte{}, false
	}
	for i := 0; i < 32; i++ { hs.rs[i] = ns[i] }
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	if !valid2 {
		return hs, []byte{}, false
	}
	return hs, plaintext, (valid1 && valid2)
}

func readMessageB(hs *handshakestate, message *messagebuffer) (*handshakestate, []byte, bool) {
	valid1 := true
	hs.re = message.ne
	mixHash(&hs.ss, hs.re[:])
	/* No PSK, so skipping mixKey */
	mixKey(&hs.ss, dh(hs.e.sk, hs.re))
	_, ns, valid1 := decryptAndHash(&hs.ss, message.ns)
	if !valid1 || len(ns) != 32 {
		return hs, []byte{}, false
	}
	for i := 0; i < 32; i++ { hs.rs[i] = ns[i] }
	mixKey(&hs.ss, dh(hs.e.sk, hs.rs))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	if !valid2 {
		return hs, []byte{}, false
	}
	return hs, plaintext, (valid1 && valid2)
}

func readMessageC(hs *handshakestate, message *messagebuffer) ([32]byte, []byte, bool, cipherstate, cipherstate) {
	valid1 := true
	mixKey(&hs.ss, dh(hs.e.sk, hs.rs))
	_, plaintext, valid2 := decryptAndHash(&hs.ss, message.ciphertext)
	if !valid2 {
		return emptyKey, []byte{}, false, hs.ss.cs, hs.ss.cs
	}
	cs1, cs2 := split(&hs.ss)
	return hs.ss.h, plaintext, (valid1 && valid2), cs1, cs2
}

func readMessageRegular(cs *cipherstate, message *messagebuffer) (*cipherstate, []byte, bool) {
	/* No encrypted keys */
	csi, plaintext, valid2 := decryptWithAd(cs, []byte{}, message.ciphertext)
	if !valid2 {
		return cs, []byte{}, false
	}
	return csi, plaintext, valid2
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
	session.mc = 0
	return session
}

func SendMessage(session *noisesession, message []byte) (*noisesession, messagebuffer) {
	var hs handshakestate
	var messageBuffer messagebuffer
	hs = session.hs
	if session.mc == 0 {
		_, messageBuffer = writeMessageA(&hs, message)
	}
	if session.mc == 1 {
		_, messageBuffer = writeMessageB(&hs, message)
	}
	if session.mc == 2 {
		session.h, messageBuffer, session.cs1, session.cs2 = writeMessageC(&hs, message)
		session.hs = handshakestate{}
	}
	if session.mc > 2 {
		if hs.i {
			_, messageBuffer = writeMessageRegular(&session.cs1, message)
		} else {
			_, messageBuffer = writeMessageRegular(&session.cs2, message)
		}
	}
	session.mc = session.mc + 1
	session.hs = hs
	return session, messageBuffer
}

func RecvMessage(session *noisesession, message *messagebuffer) (*noisesession, []byte, bool) {
	var hs handshakestate
	var plaintext []byte
	var valid bool
	hs = session.hs
	if session.mc == 0 {
		_, plaintext, valid = readMessageA(&hs, message)
	}
	if session.mc == 1 {
		_, plaintext, valid = readMessageB(&hs, message)
	}
	if session.mc == 2 {
		session.h, plaintext, valid, session.cs1, session.cs2 = readMessageC(&hs, message)
		session.hs = handshakestate{}
	}
	if session.mc > 2 {
		if hs.i {
			_, plaintext, valid = readMessageRegular(&session.cs2, message)
		} else {
			_, plaintext, valid = readMessageRegular(&session.cs1, message)
		}
	}
	session.mc = session.mc + 1
	session.hs = hs
	return session, plaintext, valid
}

func main() {}
