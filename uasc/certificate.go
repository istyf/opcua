package uasc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func parseFirstCertificate(cert []byte) (*x509.Certificate, error) {
	if len(cert) == 0 {
		return nil, errors.New("empty certificate")
	}

	if certs, err := x509.ParseCertificates(cert); err == nil && len(certs) > 0 {
		return certs[0], nil
	}

	var pemCerts [][]byte
	rest := cert
	for len(rest) > 0 {
		block, remaining := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = remaining
		if block.Type != "CERTIFICATE" {
			continue
		}
		pemCerts = append(pemCerts, block.Bytes)
	}
	if len(pemCerts) == 0 {
		return nil, errors.New("failed to parse certificate")
	}

	parsed, err := x509.ParseCertificates(pemCerts[0])
	if err != nil || len(parsed) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("failed to parse certificate")
	}
	return parsed[0], nil
}

func certificatePublicKeyType(cert *x509.Certificate) string {
	switch cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	case ed25519.PublicKey:
		return "Ed25519"
	default:
		return fmt.Sprintf("%T", cert.PublicKey)
	}
}
