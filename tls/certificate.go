package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"strings"
	"time"
)

func validateCertificateChain(chain []*x509.Certificate, domainName string) ([]*x509.Certificate, error) {
	intermediates := x509.NewCertPool()
	for _, icert := range chain[1:] {
		intermediates.AddCert(icert)
	}

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		DNSName:       domainName,
	}

	chains, err := chain[0].Verify(opts)
	if err != nil {
		return nil, err
	}
	return chains[0], nil
}

func verifyCertificateVerify(cv certificateVerify, cert *x509.Certificate, transcript []byte) error {
	transcriptHash := sha256.Sum256(transcript)

	var content bytes.Buffer
	for range 64 {
		content.WriteByte(0x20)
	}
	content.Write([]byte("TLS 1.3, server CertificateVerify"))
	content.WriteByte(0x00)
	content.Write(transcriptHash[:])

	contentHash := sha256.Sum256(content.Bytes())

	switch cv.algorithm {
	case ecdsaSecp256r1Sha256:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("expected ecdsa_secp256r1_sha256 public key")
		}
		if !ecdsa.VerifyASN1(pubKey, contentHash[:], cv.signature) {
			return fmt.Errorf("bad signature")
		}
	default:
		return fmt.Errorf("unsupported signature algorithm: 0x%04x", cv.algorithm)
	}

	return nil
}

func formatCertificate(cert *x509.Certificate) string {
	return fmt.Sprintf(
		`Certificate {
    subject:        %v
    issuer:         %v
    serial:         %x
    notBefore:      %v
    notAfter:       %v
    dnsNames:       %v
    pubKeyAlgo:     %v
    signatureAlgo:  %v
}`,
		cert.Subject,
		cert.Issuer,
		cert.SerialNumber,
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339),
		cert.DNSNames,
		cert.PublicKeyAlgorithm,
		cert.SignatureAlgorithm,
	)
}

func formatCertificateChain(certs []*x509.Certificate) string {
	var b strings.Builder
	for _, cert := range certs {
		fmt.Fprintf(&b, "%s\n", formatCertificate(cert))
	}
	return b.String()
}
