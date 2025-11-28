package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
)

var logger = log.New(os.Stderr, "[ TLS ] ", log.LstdFlags)

type Conn struct {
	rawConn     net.Conn
	transcript  []byte
	privKey     *ecdh.PrivateKey
	clientHello *clientHello
	serverHello *serverHello
	serverCert  *x509.Certificate
	hsKeys      trafficKeys
	appKeys     trafficKeys
	appDataBuf  bytes.Buffer
}

func Dial(network string, hostname string, port int) (*Conn, error) {
	address := fmt.Sprintf("%s:%d", hostname, port)
	raw, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	privKey := generateNewPrivateKey()
	conn := &Conn{
		rawConn:     raw,
		privKey:     privKey,
		clientHello: newClientHello(hostname, privKey),
	}

	if err := conn.handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	return conn, nil
}

func (conn *Conn) readRecord() (*record, error) {
	return readRecord(conn.rawConn)
}

func (conn *Conn) sendRecord(record *record) error {
	_, err := conn.rawConn.Write(record.marshal())
	if err != nil {
		return fmt.Errorf("send TLS record: %w", err)
	}
	return nil
}

func (conn *Conn) addToTranscript(msg []byte) {
	conn.transcript = append(conn.transcript, msg...)
}

func (conn *Conn) sendClientHello() error {
	clientHelloBytes := conn.clientHello.marshal()

	if err := conn.sendRecord(newRecord(recordTypeHandshake, clientHelloBytes)); err != nil {
		return fmt.Errorf("send Client Hello: %w", err)
	}

	conn.addToTranscript(clientHelloBytes)
	logger.Printf("Client Hello sent:\n%v\n\n", conn.clientHello)
	return nil
}

func (conn *Conn) receiveServerHello() error {
	record, err := conn.readRecord()
	if err != nil {
		return fmt.Errorf("read Server Hello: %w", err)
	}
	if record.typ != recordTypeHandshake {
		return fmt.Errorf("received record type %d, expected %d (handshake)", record.typ, recordTypeHandshake)
	}

	serverHello, err := parseServerHello(record.payload)
	if err != nil {
		return fmt.Errorf("parse Server Hello: %w", err)
	}
	conn.serverHello = serverHello

	conn.addToTranscript(record.payload)
	logger.Printf("Server Hello received:\n%s\n\n", serverHello)
	return nil
}

func (conn *Conn) calculateHandshakeKeys() {
	conn.hsKeys = computeHandshakeKeys(conn.privKey, conn.serverHello.pubBytes, conn.transcript)
	logger.Printf("Handshake keys calculated:\n%v\n\n", conn.hsKeys)
}

func (conn *Conn) calculateApplicationKeys() {
	conn.appKeys = computeApplicationKeys(conn.hsKeys.secret, conn.transcript)
	logger.Printf("Application keys calculated:\n%v\n\n", conn.appKeys)
}

func (conn *Conn) decryptHandshakeRecord(record *record) *record {
	return record.decrypt(&conn.hsKeys.server)
}

func (conn *Conn) decryptApplicationRecord(record *record) *record {
	return record.decrypt(&conn.appKeys.server)
}

func (conn *Conn) encryptHandshakeRecord(payload []byte) *record {
	return newRecord(recordTypeHandshake, payload).encrypt(&conn.hsKeys.client)
}

func (conn *Conn) encryptApplicationRecord(payload []byte) *record {
	return newRecord(recordTypeApplicationData, payload).encrypt(&conn.appKeys.client)
}

func (conn *Conn) receiveEncryptedExtensions() error {
	wrapper, err := conn.readRecord()
	if err != nil {
		return fmt.Errorf("read Encrypted Extensions: %w", err)
	}
	if wrapper.typ == recordTypeChangeCipherSpec {
		logger.Printf("Server Change Cipher Spec received\n\n")
		wrapper, err = conn.readRecord()
		if err != nil {
			return fmt.Errorf("read Encrypted Extensions: %w", err)
		}
	}

	record := conn.decryptHandshakeRecord(wrapper)
	extensions, err := parseEncryptedExtensions(record.payload)
	if err != nil {
		return fmt.Errorf("parse Encrypted Extensions: %w", err)
	}

	conn.addToTranscript(record.payload)
	logger.Printf("Encrypted Extensions received (%v bytes)\n\n", len(extensions))
	return nil
}

func (conn *Conn) receiveCertificate() error {
	wrapper, err := conn.readRecord()
	if err != nil {
		return fmt.Errorf("read Certificate: %w", err)
	}

	record := conn.decryptHandshakeRecord(wrapper)
	certs, err := parseCertificate(record.payload)
	if err != nil {
		return fmt.Errorf("parse Certificate: %w", err)
	}

	chain, err := validateCertificateChain(certs, conn.clientHello.hostname)
	if err != nil {
		return fmt.Errorf("invalid Certificate: %w", err)
	}
	conn.serverCert = chain[0]

	conn.addToTranscript(record.payload)
	logger.Printf("Server Certificate received and validated:\n%v\n\n", formatCertificateChain(chain))
	return nil
}

func (conn *Conn) receiveCertificateVerify() error {
	wrapper, err := conn.readRecord()
	if err != nil {
		return fmt.Errorf("read Certificate Verify: %w", err)
	}

	record := conn.decryptHandshakeRecord(wrapper)
	certVerify, err := parseCertificateVerify(record.payload)
	if err != nil {
		return fmt.Errorf("parse Certificate Verify: %w", err)
	}

	if err := verifyCertificateVerify(certVerify, conn.serverCert, conn.transcript); err != nil {
		return fmt.Errorf("invalid Certificate Verify: %w", err)
	}

	conn.addToTranscript(record.payload)
	logger.Printf("Server Certificate Verify received and verified:\n%v\n\n", certVerify)
	return nil
}

func (conn *Conn) receiveServerFinished() error {
	wrapper, err := conn.readRecord()
	if err != nil {
		return fmt.Errorf("read Server Finished: %w", err)
	}

	record := conn.decryptHandshakeRecord(wrapper)
	serverFinished, err := parseServerFinished(record.payload)
	if err != nil {
		return fmt.Errorf("parse Server Finished: %w", err)
	}

	if err := serverFinished.verify(conn.hsKeys.server.finished, conn.transcript); err != nil {
		return fmt.Errorf("invalid Server Finished: %w", err)
	}

	conn.addToTranscript(record.payload)
	logger.Printf("Server Finished received and verified:\n%v\n\n", serverFinished)
	return nil
}

func (conn *Conn) sendClientFinished() error {
	clientFinished := newClientFinished(conn.hsKeys.client.finished, conn.transcript)

	wrapper := conn.encryptHandshakeRecord(clientFinished.marshal())
	if err := conn.sendRecord(wrapper); err != nil {
		return fmt.Errorf("send Client Fnished: %w", err)
	}

	logger.Printf("Client Finished sent:\n%+v\n\n", clientFinished)
	return nil
}

func (conn *Conn) handshake() error {
	if err := conn.sendClientHello(); err != nil {
		return err
	}
	if err := conn.receiveServerHello(); err != nil {
		return err
	}

	conn.calculateHandshakeKeys()

	if err := conn.receiveEncryptedExtensions(); err != nil {
		return err
	}
	if err := conn.receiveCertificate(); err != nil {
		return err
	}
	if err := conn.receiveCertificateVerify(); err != nil {
		return err
	}
	if err := conn.receiveServerFinished(); err != nil {
		return err
	}
	if err := conn.sendClientFinished(); err != nil {
		return err
	}

	conn.calculateApplicationKeys()
	return nil
}

func (conn *Conn) sendApplicationData(data []byte) error {
	wrapper := conn.encryptApplicationRecord(data)
	if err := conn.sendRecord(wrapper); err != nil {
		return fmt.Errorf("send Application Data: %w", err)
	}

	logger.Printf("Application Data sent (%v bytes)\n\n", len(data))
	return nil
}

func (conn *Conn) receiveApplicationData() ([]byte, error) {
	wrapper, err := readRecord(conn.rawConn)
	if err != nil {
		return nil, fmt.Errorf("read Application Data: %w", err)
	}

	record := conn.decryptApplicationRecord(wrapper)
	switch record.typ {
	case recordTypeApplicationData:
		logger.Printf("Application Data received (%v bytes)\n\n", len(record.payload))
		return record.payload, nil
	default:
		logger.Printf("New Session Ticket received\n\n")
		return nil, nil
	}
}

const writeChunkSize = 8 * 1024

func (conn *Conn) Write(data []byte) (int, error) {
	total := 0

	for len(data) > 0 {
		chunkSize := min(len(data), writeChunkSize)
		if err := conn.sendApplicationData(data[:chunkSize]); err != nil {
			return total, err
		}
		total += chunkSize
		data = data[chunkSize:]
	}

	return total, nil
}

func (conn *Conn) Read(p []byte) (int, error) {
	if conn.appDataBuf.Len() > 0 {
		return conn.appDataBuf.Read(p)
	}

	var data []byte
	var err error

	for len(data) == 0 {
		data, err = conn.receiveApplicationData()
		if err != nil {
			return 0, err
		}
	}

	conn.appDataBuf.Write(data)
	return conn.appDataBuf.Read(p)
}

func (conn *Conn) Close() error {
	return conn.rawConn.Close()
}
