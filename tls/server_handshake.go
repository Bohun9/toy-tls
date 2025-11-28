package tls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type serverHello struct {
	random      []byte
	pubBytes    []byte
	version     uint16
	cipherSuite uint16
	group       uint16
}

func (sh *serverHello) String() string {
	return fmt.Sprintf(`serverHello {
    random:             %x
    pubBytes:           %x
    version:            0x%04x
    cipherSuite:        0x%04x
    group:              0x%04x
}`,
		sh.random,
		sh.pubBytes,
		sh.version,
		sh.cipherSuite,
		sh.group,
	)
}

func readBytes(r io.Reader, n int) []byte {
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		panic(err)
	}
	return b
}

func readUint8(r io.Reader) uint8 {
	var n uint8
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		panic(err)
	}
	return n
}

func readUint16(r io.Reader) uint16 {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		panic(err)
	}
	return n
}

func skipBytes(r io.Reader, n int) {
	readBytes(r, n)
}

func readVector(r io.Reader, lenBytes int) []byte {
	var length int
	switch lenBytes {
	case 1:
		length = int(readUint8(r))
	case 2:
		length = int(readUint16(r))
	case 3:
		length = int(readUint8(r))<<16 + int(readUint16(r))
	default:
		panic("unsupported vector length")
	}
	return readBytes(r, length)
}

func parseServerHello(msg []byte) (*serverHello, error) {
	r := bytes.NewReader(msg)
	serverHello := &serverHello{}

	skipBytes(r, 4)                         // header
	skipBytes(r, 2)                         // legacy_version
	serverHello.random = readBytes(r, 32)   // random
	readVector(r, 1)                        // legacy_session_id_echo
	serverHello.cipherSuite = readUint16(r) // cipher_suite
	skipBytes(r, 1)                         // legacy_compression_method
	extensions := bytes.NewReader(readVector(r, 2))

	for extensions.Len() > 0 {
		extType := readUint16(extensions)
		extData := bytes.NewReader(readVector(extensions, 2))

		switch extType {
		case extensionTypeKeyShare:
			serverHello.group = readUint16(extData)
			serverHello.pubBytes = readVector(extData, 2)
		case extensionTypeSupportedVersions:
			serverHello.version = readUint16(extData)
		}
	}

	return serverHello, nil
}

func parseEncryptedExtensions(msg []byte) ([]byte, error) {
	r := bytes.NewReader(msg)
	skipBytes(r, 4)
	return readVector(r, 2), nil
}

func parseCertificate(msg []byte) ([]byte, error) {
	r := bytes.NewReader(msg)
	skipBytes(r, 4)
	readVector(r, 1)             // request context
	return readVector(r, 3), nil // certificates entries
}

func parseCertificateVerify(msg []byte) ([]byte, error) {
	r := bytes.NewReader(msg)
	skipBytes(r, 4)
	skipBytes(r, 2) // signature scheme
	return readVector(r, 2), nil
}

type serverFinished struct {
	verifyData []byte
}

func (sf *serverFinished) String() string {
	return fmt.Sprintf(
		`serverFinished {
    verifyData: %x
}`,
		sf.verifyData)
}

func parseServerFinished(msg []byte) (*serverFinished, error) {
	r := bytes.NewReader(msg)
	serverFinished := &serverFinished{}

	skipBytes(r, 4)
	serverFinished.verifyData = readBytes(r, hashLen)

	return serverFinished, nil
}
