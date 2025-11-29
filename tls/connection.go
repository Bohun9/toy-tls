package tls

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

type handshakeState struct {
	hostname    string
	transcript  []byte
	privKey     *ecdh.PrivateKey
	keys        trafficKeys
	serverHello *serverHello
	serverCert  *x509.Certificate
}

func (s *handshakeState) addToTranscript(content []byte) {
	s.transcript = append(s.transcript, content...)
}

type Conn struct {
	rawConn      net.Conn
	hs           *handshakeState
	appDataBuf   bytes.Buffer
	messageLayer messageLayer
	recordLayer  recordLayer
	logger       *log.Logger
}

func Dial(network string, hostname string, port int, verbose bool) (*Conn, error) {
	address := fmt.Sprintf("%s:%d", hostname, port)
	raw, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}

	var logger *log.Logger
	if verbose {
		logger = log.New(os.Stderr, "[ TLS ] ", log.LstdFlags)
	} else {
		logger = log.New(io.Discard, "", log.LstdFlags)
	}

	recordLayer := newRecordLayerImpl(raw)
	conn := &Conn{
		rawConn: raw,
		hs: &handshakeState{
			hostname: hostname,
			privKey:  generateNewPrivateKey(),
		},
		messageLayer: newMessageLayerImpl(recordLayer),
		recordLayer:  recordLayer,
		logger:       logger,
	}

	if err := conn.handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	return conn, nil
}

func (c *Conn) connected() bool {
	return c.hs == nil
}

// handles async messages
func (c *Conn) readMessage() (*message, error) {
	msg, err := c.messageLayer.readMessage()
	if err != nil {
		return nil, err
	}

	if msg.contentType == contentTypeAlert {
		alertDescription := msg.content[1]
		return nil, fmt.Errorf("received alert: 0x%02x", alertDescription)
	}

	if msg.contentType == contentTypeChangeCipherSpec {
		c.logger.Printf("Server Change Cipher Spec received\n\n")
		return c.readMessage()
	}

	if msg.contentType == contentTypeHandshake && c.connected() {
		handshakeType := msg.content[0]
		switch handshakeType {
		case handshakeTypeNewSessionTicket:
			c.logger.Printf("New Session Ticket received\n\n")
			return c.readMessage()
		default:
			return nil, fmt.Errorf("unsupported post-handshake message: 0x%02x", handshakeType)
		}
	}

	return msg, err
}

func (c *Conn) readHandshakeMessage() ([]byte, error) {
	msg, err := c.readMessage()
	if err != nil {
		return nil, err
	}

	if msg.contentType != contentTypeHandshake {
		return nil, fmt.Errorf("expected handshake message, got 0x%02x", msg.contentType)
	} else {
		return msg.content, nil
	}
}

func (c *Conn) sendMessage(msg *message) (int, error) {
	return c.messageLayer.writeMessage(msg)
}

func (c *Conn) addToTranscript(content []byte) {
	c.hs.addToTranscript(content)
}

func (c *Conn) sendClientHello() error {
	clientHello := newClientHello(c.hs.hostname, c.hs.privKey)
	msg := clientHello.marshal()

	if _, err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("send Client Hello: %w", err)
	}

	c.addToTranscript(msg.content)
	c.logger.Printf("Client Hello sent:\n%v\n\n", clientHello)
	return nil
}

func (c *Conn) receiveServerHello() error {
	content, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read Server Hello: %w", err)
	}

	serverHello, err := parseServerHello(content)
	if err != nil {
		return fmt.Errorf("parse Server Hello: %w", err)
	}
	c.hs.serverHello = serverHello

	c.addToTranscript(content)
	c.logger.Printf("Server Hello received:\n%s\n\n", serverHello)
	return nil
}

func (c *Conn) calculateHandshakeKeys() {
	hsKeys := computeHandshakeKeys(c.hs.privKey, c.hs.serverHello.pubBytes, c.hs.transcript)
	c.recordLayer.updateKeys(&hsKeys)

	c.hs.keys = hsKeys
	c.logger.Printf("Handshake keys calculated:\n%v\n\n", hsKeys)
}

func (c *Conn) calculateApplicationKeys() {
	appKeys := computeApplicationKeys(c.hs.keys.secret, c.hs.transcript)
	c.recordLayer.updateKeys(&appKeys)

	c.logger.Printf("Application keys calculated:\n%v\n\n", appKeys)
}

func (c *Conn) receiveEncryptedExtensions() error {
	content, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read Encrypted Extensions: %w", err)
	}

	extensions, err := parseEncryptedExtensions(content)
	if err != nil {
		return fmt.Errorf("parse Encrypted Extensions: %w", err)
	}

	c.addToTranscript(content)
	c.logger.Printf("Encrypted Extensions received (%v bytes)\n\n", len(extensions))
	return nil
}

func (c *Conn) receiveCertificate() error {
	content, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read Certificate: %w", err)
	}

	certs, err := parseCertificate(content)
	if err != nil {
		return fmt.Errorf("parse Certificate: %w", err)
	}

	chain, err := validateCertificateChain(certs, c.hs.hostname)
	if err != nil {
		return fmt.Errorf("invalid Certificate: %w", err)
	}
	c.hs.serverCert = chain[0]

	c.addToTranscript(content)
	c.logger.Printf("Server Certificate received and validated:\n%v\n\n", formatCertificateChain(chain))
	return nil
}

func (c *Conn) receiveCertificateVerify() error {
	content, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read Certificate Verify: %w", err)
	}

	certVerify, err := parseCertificateVerify(content)
	if err != nil {
		return fmt.Errorf("parse Certificate Verify: %w", err)
	}

	if err := verifyCertificateVerify(certVerify, c.hs.serverCert, c.hs.transcript); err != nil {
		return fmt.Errorf("invalid Certificate Verify: %w", err)
	}

	c.addToTranscript(content)
	c.logger.Printf("Server Certificate Verify received and verified:\n%v\n\n", certVerify)
	return nil
}

func (c *Conn) receiveServerFinished() error {
	content, err := c.readHandshakeMessage()
	if err != nil {
		return fmt.Errorf("read Server Finished: %w", err)
	}

	serverFinished, err := parseServerFinished(content)
	if err != nil {
		return fmt.Errorf("parse Server Finished: %w", err)
	}

	if err := serverFinished.verify(c.hs.keys.server.finished, c.hs.transcript); err != nil {
		return fmt.Errorf("invalid Server Finished: %w", err)
	}

	c.addToTranscript(content)
	c.logger.Printf("Server Finished received and verified:\n%v\n\n", serverFinished)
	return nil
}

func (c *Conn) sendClientFinished() error {
	clientFinished := newClientFinished(c.hs.keys.client.finished, c.hs.transcript)
	msg := clientFinished.marshal()

	if _, err := c.sendMessage(msg); err != nil {
		return fmt.Errorf("send Client Finished: %w", err)
	}

	c.logger.Printf("Client Finished sent:\n%+v\n\n", clientFinished)
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

	c.hs = nil
	return nil
}

func (c *Conn) sendApplicationData(data []byte) (int, error) {
	msg := newMessage(contentTypeApplicationData, data)

	n, err := c.sendMessage(msg)
	if err != nil {
		return n, fmt.Errorf("send Application Data: %w", err)
	}

	c.logger.Printf("Application Data sent (%v bytes)\n\n", len(data))
	return n, nil
}

func (c *Conn) receiveApplicationData() ([]byte, error) {
	msg, err := c.readMessage()
	if err != nil {
		return nil, fmt.Errorf("read Application Data: %w", err)
	}

	c.logger.Printf("Application Data received (%v bytes)\n\n", len(msg.content))
	return msg.content, nil
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
