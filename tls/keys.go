package tls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

var hashLen int = sha256.New().Size()

const (
	keyLen = 16
	ivLen  = 12
)

func generateNewPrivateKey() *ecdh.PrivateKey {
	curve := ecdh.P256()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return privKey
}

type encryptionKeys struct {
	key      []byte
	iv       []byte
	finished []byte
	seq      uint64
}

func (ek *encryptionKeys) String() string {
	return fmt.Sprintf(`encryptionKeys {
                key:      %x
                iv:       %x
                finished: %x
                seq:      %d
            }`,
		ek.key,
		ek.iv,
		ek.finished,
		ek.seq,
	)
}

func xorNonce(iv []byte, seq uint64) []byte {
	nonce := append([]byte(nil), iv...)
	for i := range 8 {
		nonce[len(nonce)-1-i] ^= byte(seq >> (8 * i))
	}
	return nonce
}

func (ek *encryptionKeys) decrypt(ciphertext []byte, ad []byte) ([]byte, error) {
	nonce := xorNonce(ek.iv, ek.seq)
	ek.seq++

	return decrypt(ek.key, nonce, ciphertext, ad)
}

func (ek *encryptionKeys) encrypt(plaintext []byte, ad []byte) []byte {
	nonce := xorNonce(ek.iv, ek.seq)
	ek.seq++

	return encrypt(ek.key, nonce, plaintext, ad)
}

type trafficKeys struct {
	secret []byte
	client encryptionKeys
	server encryptionKeys
}

func (tk trafficKeys) String() string {
	return fmt.Sprintf(`trafficKeys {
    secret: %x
    client: %v
    server: %v
}`,
		tk.secret,
		&tk.client,
		&tk.server,
	)
}

func hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel bytes.Buffer
	binary.Write(&hkdfLabel, binary.BigEndian, uint16(length))
	hkdfLabel.Write(marshalVector(1, []byte("tls13 "+label)))
	hkdfLabel.Write(marshalVector(1, context))

	key, err := hkdf.Expand(sha256.New, secret, hkdfLabel.String(), length)
	if err != nil {
		panic(err)
	}
	return key
}

func hkdfExtract(secret []byte, salt []byte) []byte {
	key, err := hkdf.Extract(sha256.New, secret, salt)
	if err != nil {
		panic(err)
	}
	return key
}

func deriveSecret(secret []byte, label string, transcript []byte) []byte {
	transcriptHash := sha256.Sum256(transcript)
	return hkdfExpandLabel(secret, label, transcriptHash[:], hashLen)
}

func deriveWriteKeys(secret []byte) encryptionKeys {
	key := hkdfExpandLabel(secret, "key", nil, keyLen)
	iv := hkdfExpandLabel(secret, "iv", nil, ivLen)
	fin := hkdfExpandLabel(secret, "finished", nil, hashLen)

	return encryptionKeys{
		key:      key,
		iv:       iv,
		finished: fin,
		seq:      0,
	}
}

func computeHandshakeKeys(privKey *ecdh.PrivateKey, peerPubBytes, transcript []byte) trafficKeys {
	curve := privKey.Curve()
	peerPubKey, err := curve.NewPublicKey(peerPubBytes)
	if err != nil {
		panic(err)
	}

	sharedSecret, err := privKey.ECDH(peerPubKey)
	if err != nil {
		panic(err)
	}

	zeroSalt := make([]byte, hashLen)
	preSharedSecret := make([]byte, hashLen)

	earlySecret := hkdfExtract(preSharedSecret, zeroSalt)
	derivedSalt := deriveSecret(earlySecret, "derived", nil)
	handshakeSecret := hkdfExtract(sharedSecret, derivedSalt)
	clientHsSecret := deriveSecret(handshakeSecret, "c hs traffic", transcript)
	serverHsSecret := deriveSecret(handshakeSecret, "s hs traffic", transcript)

	return trafficKeys{
		secret: handshakeSecret,
		client: deriveWriteKeys(clientHsSecret),
		server: deriveWriteKeys(serverHsSecret),
	}
}

func computeApplicationKeys(handshakeSecret []byte, transcript []byte) trafficKeys {
	zeroSecret := make([]byte, hashLen)
	derivedSalt := deriveSecret(handshakeSecret, "derived", nil)

	masterSecret := hkdfExtract(zeroSecret, derivedSalt)
	clientAppSecret := deriveSecret(masterSecret, "c ap traffic", transcript)
	serverAppSecret := deriveSecret(masterSecret, "s ap traffic", transcript)

	return trafficKeys{
		secret: masterSecret,
		client: deriveWriteKeys(clientAppSecret),
		server: deriveWriteKeys(serverAppSecret),
	}
}

func aes128gcmsha256(key []byte) cipher.AEAD {
	aes128, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	gcm, err := cipher.NewGCM(aes128)
	if err != nil {
		panic(err)
	}
	return gcm
}

func decrypt(key []byte, nonce []byte, ciphertext []byte, ad []byte) ([]byte, error) {
	return aes128gcmsha256(key).Open(nil, nonce, ciphertext, ad)
}

func encrypt(key []byte, nonce []byte, plaintext []byte, ad []byte) []byte {
	return aes128gcmsha256(key).Seal(nil, nonce, plaintext, ad)
}

func computeVerifyData(key []byte, transcript []byte) []byte {
	transcriptHash := sha256.Sum256(transcript)

	mac := hmac.New(sha256.New, key)
	mac.Write(transcriptHash[:])
	return mac.Sum(nil)
}
