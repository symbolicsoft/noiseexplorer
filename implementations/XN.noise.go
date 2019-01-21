/*
XN:
	-> e
	<- e, ee
	-> s, se
	<-
	->
*/

/* ---------------------------------------------------------------- *
 * PARAMETERS                                                       *
 * ---------------------------------------------------------------- */

package main

import (
	"crypto/rand"
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

func getPublicKey(kp keypair) [32]byte {
	return kp.pk
}

func isEmptyKey(k [32]byte) bool {
	var result bool
	result = true
	for _, v := range k {
		if v != 0 {
			result = false
		}
	}
	return result
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

func initializeInitiator(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_XN_25519_ChaChaPoly_BLAKE2s")
	ss = mixHash(initializeSymmetric(name), prologue)
	return handshakestate{ss, s, e, rs, re, psk, true}
}

func initializeResponder(prologue []byte, s keypair, rs [32]byte, psk [32]byte) handshakestate {
	var ss symmetricstate
	var e keypair
	var re [32]byte
	name := []byte("Noise_XN_25519_ChaChaPoly_BLAKE2s")
	ss = mixHash(initializeSymmetric(name), prologue)
	return handshakestate{ss, s, e, rs, re, psk, false}
}

func writeMessageA(hs handshakestate, payload []byte) (handshakestate, messagebuffer) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	e = generateKeypair()
	ne = e.pk
	ss = mixHash(ss, ne[:])
	/* No PSK, so skipping mixKey */
	ss, ciphertext = encryptAndHash(ss, payload)
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func writeMessageB(hs handshakestate, payload []byte) (handshakestate, messagebuffer) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	e = generateKeypair()
	ne = e.pk
	ss = mixHash(ss, ne[:])
	/* No PSK, so skipping mixKey */
	ss = mixKey(ss, dh(e.sk, re))
	ss, ciphertext = encryptAndHash(ss, payload)
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func writeMessageC(hs handshakestate, payload []byte) (handshakestate, messagebuffer, cipherstate, cipherstate) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	ss, ns = encryptAndHash(ss, s.pk[:])
	ss = mixKey(ss, dh(s.sk, re))
	ss, ciphertext = encryptAndHash(ss, payload)
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	cs1, cs2 := split(ss)
	return hs, messageBuffer, cs1, cs2
}

func writeMessageD(hs handshakestate, payload []byte) (handshakestate, messagebuffer) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	ne, ns, ciphertext := emptyKey, []byte{}, []byte{}
	ss, ciphertext = encryptAndHash(ss, payload)
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	messageBuffer := messagebuffer{ne, ns, ciphertext}
	return hs, messageBuffer
}

func readMessageA(hs handshakestate, message messagebuffer) (handshakestate, []byte, bool) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	valid1 := true
	re = message.ne
	ss = mixHash(ss, re[:])
	/* No PSK, so skipping mixKey */
	ss, plaintext, valid2 := decryptAndHash(ss, message.ciphertext)
	if !valid2 {
		return hs, []byte{}, false
	}
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	return hs, plaintext, (valid1 && valid2)
}

func readMessageB(hs handshakestate, message messagebuffer) (handshakestate, []byte, bool) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	valid1 := true
	re = message.ne
	ss = mixHash(ss, re[:])
	/* No PSK, so skipping mixKey */
	ss = mixKey(ss, dh(e.sk, re))
	ss, plaintext, valid2 := decryptAndHash(ss, message.ciphertext)
	if !valid2 {
		return hs, []byte{}, false
	}
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	return hs, plaintext, (valid1 && valid2)
}

func readMessageC(hs handshakestate, message messagebuffer) (handshakestate, []byte, bool, cipherstate, cipherstate) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	valid1 := true
	ss, ns, valid1 := decryptAndHash(ss, message.ns)
	if !valid1 || len(ns) != 32 {
		return hs, []byte{}, false, hs.ss.cs, hs.ss.cs
	}
	for i := 0; i < 32; i++ {
		rs[i] = ns[i]
	}
	ss = mixKey(ss, dh(e.sk, rs))
	ss, plaintext, valid2 := decryptAndHash(ss, message.ciphertext)
	if !valid2 {
		return hs, []byte{}, false, hs.ss.cs, hs.ss.cs
	}
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	cs1, cs2 := split(ss)
	return hs, plaintext, (valid1 && valid2), cs1, cs2
}

func readMessageD(hs handshakestate, message messagebuffer) (handshakestate, []byte, bool) {
	ss, s, e, rs, re, psk, initiator := hs.ss, hs.s, hs.e, hs.rs, hs.re, hs.psk, hs.i
	valid1 := true
	ss, plaintext, valid2 := decryptAndHash(ss, message.ciphertext)
	if !valid2 {
		return hs, []byte{}, false
	}
	hs = handshakestate{ss, s, e, rs, re, psk, initiator}
	return hs, plaintext, (valid1 && valid2)
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

func SendMessage(session noisesession, message []byte) (noisesession, messagebuffer) {
	var hs handshakestate
	var messageBuffer messagebuffer
	hs = session.hs
	if session.mc == 0 {
		hs, messageBuffer = writeMessageA(hs, message)
	}
	if session.mc == 1 {
		hs, messageBuffer = writeMessageB(hs, message)
	}
	if session.mc == 2 {
		hs, messageBuffer, session.cs1, session.cs2 = writeMessageC(hs, message)
	}
	if session.mc > 2 {
		if hs.i {
			hs.ss.cs = session.cs1
		} else {
			hs.ss.cs = session.cs2
		}
		hs, messageBuffer = writeMessageD(hs, message)
		if hs.i {
			session.cs1 = hs.ss.cs
		} else {
			session.cs2 = hs.ss.cs
		}
	}
	session.mc = session.mc + 1
	session.hs = hs
	return session, messageBuffer
}

func RecvMessage(session noisesession, message messagebuffer) (noisesession, []byte, bool) {
	var hs handshakestate
	var plaintext []byte
	var valid bool
	hs = session.hs
	if session.mc == 0 {
		hs, plaintext, valid = readMessageA(hs, message)
	}
	if session.mc == 1 {
		hs, plaintext, valid = readMessageB(hs, message)
	}
	if session.mc == 2 {
		hs, plaintext, valid, session.cs1, session.cs2 = readMessageC(hs, message)
	}
	if session.mc > 2 {
		if hs.i {
			hs.ss.cs = session.cs2
		} else {
			hs.ss.cs = session.cs1
		}
		hs, plaintext, valid = readMessageD(hs, message)
		if hs.i {
			session.cs2 = hs.ss.cs
		} else {
			session.cs1 = hs.ss.cs
		}
	}
	session.mc = session.mc + 1
	session.hs = hs
	return session, plaintext, valid
}

func main() {}
