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

type handshakeState struct {
	hostname    string
	transcript  []byte
	privKey     *ecdh.PrivateKey
	keys        trafficKeys
	serverHello *serverHello
	serverCert  *x509.Certificate
}

func (s *handshakeState) addToTranscript(msg *message) {
	s.transcript = append(s.transcript, msg.content...)
}

type Conn struct {
	rawConn        net.Conn
	handshakeState *handshakeState
	appDataBuf     bytes.Buffer
	messageLayer   messageLayer
	recordLayer    recordLayer
}

func Dial(network string, hostname string, port int) (*Conn, error) {
	address := fmt.Sprintf("%s:%d", hostname, port)
	raw, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	recordLayer := newRecordLayerImpl(raw)
	conn := &Conn{
		rawConn: raw,
		handshakeState: &handshakeState{
			hostname: hostname,
			privKey:  generateNewPrivateKey(),
		},
		messageLayer: newMessageLayerImpl(recordLayer),
		recordLayer:  recordLayer,
	}

	if err := conn.handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	return conn, nil
}

func (c *Conn) readMessage() (*message, error) {
	msg, err := c.messageLayer.readMessage()
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}
	return msg, nil
}

func (c *Conn) sendMessage(msg *message) (int, error) {
	return c.messageLayer.writeMessage(msg)
}

func (c *Conn) addToTranscript(msg *message) {
	c.handshakeState.addToTranscript(msg)
}

func (c *Conn) sendClientHello() error {
	clientHello := newClientHello(c.handshakeState.hostname, c.handshakeState.privKey)
	msg := clientHello.marshal()

	if _, err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("send Client Hello: %w", err)
	}

	c.addToTranscript(msg)
	logger.Printf("Client Hello sent:\n%v\n\n", clientHello)
	return nil
}

func (c *Conn) receiveServerHello() error {
	msg, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("read Server Hello: %w", err)
	}
	if msg.contentType != contentTypeHandshake {
		return fmt.Errorf("received content type %d, expected handshake", msg.contentType)
	}

	serverHello, err := parseServerHello(msg.content)
	if err != nil {
		return fmt.Errorf("parse Server Hello: %w", err)
	}
	c.handshakeState.serverHello = serverHello

	c.addToTranscript(msg)
	logger.Printf("Server Hello received:\n%s\n\n", serverHello)
	return nil
}

func (c *Conn) calculateHandshakeKeys() {
	hsKeys := computeHandshakeKeys(c.handshakeState.privKey, c.handshakeState.serverHello.pubBytes, c.handshakeState.transcript)
	c.recordLayer.updateKeys(&hsKeys)

	c.handshakeState.keys = hsKeys
	logger.Printf("Handshake keys calculated:\n%v\n\n", hsKeys)
}

func (c *Conn) calculateApplicationKeys() {
	appKeys := computeApplicationKeys(c.handshakeState.keys.secret, c.handshakeState.transcript)
	c.recordLayer.updateKeys(&appKeys)

	logger.Printf("Application keys calculated:\n%v\n\n", appKeys)
}

func (c *Conn) receiveEncryptedExtensions() error {
	msg, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("read Encrypted Extensions: %w", err)
	}
	if msg.contentType == contentTypeChangeCipherSpec {
		logger.Printf("Server Change Cipher Spec received\n\n")
		msg, err = c.readMessage()
		if err != nil {
			return fmt.Errorf("read Encrypted Extensions: %w", err)
		}
	}

	extensions, err := parseEncryptedExtensions(msg.content)
	if err != nil {
		return fmt.Errorf("parse Encrypted Extensions: %w", err)
	}

	c.addToTranscript(msg)
	logger.Printf("Encrypted Extensions received (%v bytes)\n\n", len(extensions))
	return nil
}

func (c *Conn) receiveCertificate() error {
	msg, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("read Certificate: %w", err)
	}

	certs, err := parseCertificate(msg.content)
	if err != nil {
		return fmt.Errorf("parse Certificate: %w", err)
	}

	chain, err := validateCertificateChain(certs, c.handshakeState.hostname)
	if err != nil {
		return fmt.Errorf("invalid Certificate: %w", err)
	}
	c.handshakeState.serverCert = chain[0]

	c.addToTranscript(msg)
	logger.Printf("Server Certificate received and validated:\n%v\n\n", formatCertificateChain(chain))
	return nil
}

func (c *Conn) receiveCertificateVerify() error {
	msg, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("read Certificate Verify: %w", err)
	}

	certVerify, err := parseCertificateVerify(msg.content)
	if err != nil {
		return fmt.Errorf("parse Certificate Verify: %w", err)
	}

	if err := verifyCertificateVerify(certVerify, c.handshakeState.serverCert, c.handshakeState.transcript); err != nil {
		return fmt.Errorf("invalid Certificate Verify: %w", err)
	}

	c.addToTranscript(msg)
	logger.Printf("Server Certificate Verify received and verified:\n%v\n\n", certVerify)
	return nil
}

func (c *Conn) receiveServerFinished() error {
	msg, err := c.readMessage()
	if err != nil {
		return fmt.Errorf("read Server Finished: %w", err)
	}

	serverFinished, err := parseServerFinished(msg.content)
	if err != nil {
		return fmt.Errorf("parse Server Finished: %w", err)
	}

	if err := serverFinished.verify(c.handshakeState.keys.server.finished, c.handshakeState.transcript); err != nil {
		return fmt.Errorf("invalid Server Finished: %w", err)
	}

	c.addToTranscript(msg)
	logger.Printf("Server Finished received and verified:\n%v\n\n", serverFinished)
	return nil
}

func (c *Conn) sendClientFinished() error {
	clientFinished := newClientFinished(c.handshakeState.keys.client.finished, c.handshakeState.transcript)
	msg := clientFinished.marshal()

	if _, err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("send Client Finished: %w", err)
	}

	logger.Printf("Client Finished sent:\n%+v\n\n", clientFinished)
	return nil
}

func (c *Conn) handshake() error {
	if err := c.sendClientHello(); err != nil {
		return err
	}
	if err := c.receiveServerHello(); err != nil {
		return err
	}

	c.calculateHandshakeKeys()

	if err := c.receiveEncryptedExtensions(); err != nil {
		return err
	}
	if err := c.receiveCertificate(); err != nil {
		return err
	}
	if err := c.receiveCertificateVerify(); err != nil {
		return err
	}
	if err := c.receiveServerFinished(); err != nil {
		return err
	}
	if err := c.sendClientFinished(); err != nil {
		return err
	}

	c.calculateApplicationKeys()
	return nil
}

func (c *Conn) sendApplicationData(data []byte) (int, error) {
	msg := newMessage(contentTypeApplicationData, data)

	n, err := c.sendMessage(msg)
	if err != nil {
		return n, fmt.Errorf("send Application Data: %w", err)
	}

	logger.Printf("Application Data sent (%v bytes)\n\n", len(data))
	return n, nil
}

func (c *Conn) receiveApplicationData() ([]byte, error) {
	msg, err := c.readMessage()
	if err != nil {
		return nil, fmt.Errorf("read Application Data: %w", err)
	}

	switch msg.contentType {
	case contentTypeApplicationData:
		logger.Printf("Application Data received (%v bytes)\n\n", len(msg.content))
		return msg.content, nil
	default:
		logger.Printf("New Session Ticket received\n\n")
		return nil, nil
	}
}

func (c *Conn) Write(data []byte) (int, error) {
	return c.sendApplicationData(data)
}

func (c *Conn) Read(p []byte) (int, error) {
	if c.appDataBuf.Len() == 0 {
		for {
			data, err := c.receiveApplicationData()
			if err != nil {
				return 0, err
			}
			if len(data) > 0 {
				c.appDataBuf.Write(data)
				break
			}
		}
	}

	return c.appDataBuf.Read(p)
}

func (c *Conn) Close() error {
	return c.rawConn.Close()
}
