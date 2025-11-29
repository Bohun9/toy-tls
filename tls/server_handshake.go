package tls

import (
	"bytes"
	"crypto/x509"
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

func parseServerHello(content []byte) (*serverHello, error) {
	r := bytes.NewReader(content)
	sh := &serverHello{}

	skipBytes(r, 4)                // header
	skipBytes(r, 2)                // legacy_version
	sh.random = readBytes(r, 32)   // random
	readVector(r, 1)               // legacy_session_id_echo
	sh.cipherSuite = readUint16(r) // cipher_suite
	skipBytes(r, 1)                // legacy_compression_method
	extensions := bytes.NewReader(readVector(r, 2))

	for extensions.Len() > 0 {
		extType := readUint16(extensions)
		extData := bytes.NewReader(readVector(extensions, 2))

		switch extType {
		case extensionTypeKeyShare:
			sh.group = readUint16(extData)
			sh.pubBytes = readVector(extData, 2)
		case extensionTypeSupportedVersions:
			sh.version = readUint16(extData)
		}
	}

	return sh, nil
}

func parseEncryptedExtensions(content []byte) ([]byte, error) {
	r := bytes.NewReader(content)
	skipBytes(r, 4)
	return readVector(r, 2), nil
}

func parseCertificate(content []byte) ([]*x509.Certificate, error) {
	r := bytes.NewReader(content)

	skipBytes(r, 4)
	readVector(r, 1)                              // request_context
	certList := bytes.NewReader(readVector(r, 3)) // certificate_list

	var certs []*x509.Certificate

	for certList.Len() > 0 {
		der := readVector(certList, 3)
		readVector(certList, 2) // extensions

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	return certs, nil
}

type certificateVerify struct {
	algorithm uint16
	signature []byte
}

func (cv *certificateVerify) String() string {
	return fmt.Sprintf(
		`certificateVerfiy{
    algorithm: 0x%04x
    signature: %x
}`,
		cv.algorithm,
		cv.signature,
	)
}

func parseCertificateVerify(content []byte) (*certificateVerify, error) {
	r := bytes.NewReader(content)
	cv := &certificateVerify{}

	skipBytes(r, 4)
	cv.algorithm = readUint16(r)
	cv.signature = readVector(r, 2)

	return cv, nil
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

func parseServerFinished(content []byte) (*serverFinished, error) {
	r := bytes.NewReader(content)
	sf := &serverFinished{}

	skipBytes(r, 4)
	sf.verifyData = readBytes(r, hashLen)

	return sf, nil
}

func (sf *serverFinished) verify(finishedKey []byte, transcript []byte) error {
	expected := computeVerifyData(finishedKey, transcript)
	if !bytes.Equal(sf.verifyData, expected) {
		return fmt.Errorf("bad verify data")
	}
	return nil
}
