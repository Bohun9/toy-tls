package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type clientHello struct {
	hostname           string
	random             []byte
	pubBytes           []byte
	supportedVersion   uint16
	cipherSuite        uint16
	supportedGroup     uint16
	signatureAlgorithm uint16
}

func (ch *clientHello) String() string {
	return fmt.Sprintf(
		`clientHello {
    hostname:           %s
    random:             %x
    pubBytes:           %x
    supportedVersion:   0x%04x
    cipherSuite:        0x%04x
    supportedGroup:     0x%04x
    signatureAlgorithm: 0x%04x
}`,
		ch.hostname,
		ch.random,
		ch.pubBytes,
		ch.supportedVersion,
		ch.cipherSuite,
		ch.supportedGroup,
		ch.signatureAlgorithm,
	)
}

func newClientHello(hostname string, privKey *ecdh.PrivateKey) *clientHello {
	random := make([]byte, 32)
	rand.Read(random)

	return &clientHello{
		hostname:           hostname,
		random:             random,
		pubBytes:           privKey.PublicKey().Bytes(),
		supportedVersion:   tlsVersion13,
		cipherSuite:        tlsAes128GcmSha256,
		supportedGroup:     secp256r1,
		signatureAlgorithm: ecdsaSecp256r1Sha256,
	}
}

func marshalVector(lenBytes int, data []byte) []byte {
	var vec bytes.Buffer
	length := len(data)

	switch lenBytes {
	case 1:
		binary.Write(&vec, binary.BigEndian, uint8(length))
	case 2:
		binary.Write(&vec, binary.BigEndian, uint16(length))
	case 3:
		binary.Write(&vec, binary.BigEndian, uint8(length>>16))
		binary.Write(&vec, binary.BigEndian, uint16(length))
	default:
		panic("unsupported vector length")
	}
	vec.Write(data)

	return vec.Bytes()
}

func marshalUint16List(xs []uint16) []byte {
	var buf bytes.Buffer
	for _, x := range xs {
		binary.Write(&buf, binary.BigEndian, x)
	}
	return buf.Bytes()
}

func serverNameEntry(hostname string) []byte {
	var entry bytes.Buffer
	entry.WriteByte(0x00) // name_type = host_name
	entry.Write(marshalVector(2, []byte(hostname)))
	return entry.Bytes()
}

func keyShareEntry(group uint16, keyExchange []byte) []byte {
	var entry bytes.Buffer
	binary.Write(&entry, binary.BigEndian, group)
	entry.Write(marshalVector(2, keyExchange))
	return entry.Bytes()
}

func marshalExtension(extType uint16, data []byte) []byte {
	var ext bytes.Buffer
	binary.Write(&ext, binary.BigEndian, extType)
	ext.Write(marshalVector(2, data))
	return ext.Bytes()
}

func (ch *clientHello) marshal() []byte {
	var msg bytes.Buffer

	// handshake header
	msg.WriteByte(handshakeTypeClientHello)
	msg.Write([]byte{0x00, 0x00, 0x00}) // length placeholder

	// client hello content
	binary.Write(&msg, binary.BigEndian, tlsVersion12)                       // legacy_version
	msg.Write(ch.random)                                                     // client_random
	msg.Write(marshalVector(1, nil))                                         // legacy_session_id
	msg.Write(marshalVector(2, marshalUint16List([]uint16{ch.cipherSuite}))) // cipher_suites
	msg.Write(marshalVector(1, []byte{nullCompressionMethod}))               // legacy_compression_methods

	// extensions
	var exts bytes.Buffer
	exts.Write(marshalExtension(extensionTypeServerName, marshalVector(2, serverNameEntry(ch.hostname))))
	exts.Write(marshalExtension(extensionTypeSupportedVersions, marshalVector(1, marshalUint16List([]uint16{ch.supportedVersion}))))
	exts.Write(marshalExtension(extensionTypeSignaturaAlgorithms, marshalVector(2, marshalUint16List([]uint16{ch.signatureAlgorithm}))))
	exts.Write(marshalExtension(extensionTypeSupportedGroups, marshalVector(2, marshalUint16List([]uint16{ch.supportedGroup}))))
	exts.Write(marshalExtension(extensionTypeKeyShare, marshalVector(2, keyShareEntry(ch.supportedGroup, ch.pubBytes))))

	msg.Write(marshalVector(2, exts.Bytes()))

	// fill the length placeholder
	data := msg.Bytes()
	length := len(data) - 4
	data[1] = byte(length >> 16)
	data[2] = byte(length >> 8)
	data[3] = byte(length)

	return data
}

type clientFinished struct {
	verifyData []byte
}

func (cf *clientFinished) String() string {
	return fmt.Sprintf(
		`clientFinished {
    verifyData: %x
}`,
		cf.verifyData)
}

func newClientFinished(key []byte, transcript []byte) *clientFinished {
	return &clientFinished{
		verifyData: computeFinishedData(key, transcript),
	}
}

func (cf *clientFinished) marshal() []byte {
	var msg bytes.Buffer
	msg.WriteByte(handshakeTypeFinished)
	msg.Write(marshalVector(3, cf.verifyData))
	return msg.Bytes()
}
