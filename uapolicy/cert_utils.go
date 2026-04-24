// Copyright 2018-2019 gopcua authors. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

package uapolicy

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/pem"

	"github.com/gopcua/opcua/errors"
)

func parseFirstCertificate(c []byte) (*x509.Certificate, error) {
	certs, err := x509.ParseCertificates(c)
	if err == nil && len(certs) > 0 {
		return certs[0], nil
	}

	for len(c) > 0 {
		var block *pem.Block
		block, c = pem.Decode(c)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		return x509.ParseCertificate(block.Bytes)
	}

	return nil, errors.Errorf("failed to parse certificate")
}

// Thumbprint returns the thumbprint of the leaf certificate in a DER-encoded
// certificate or certificate chain blob.
func Thumbprint(c []byte) ([]byte, error) {
	cert, err := parseFirstCertificate(c)
	if err != nil {
		return nil, err
	}
	thumbprint := sha1.Sum(cert.Raw)
	return thumbprint[:], nil
}

// PublicKey returns the RSA PublicKey from the leaf certificate in a DER-encoded
// certificate or certificate chain blob.
func PublicKey(c []byte) (*rsa.PublicKey, error) {
	cert, err := parseFirstCertificate(c)
	if err != nil {
		return nil, err
	}

	return cert.PublicKey.(*rsa.PublicKey), nil
}
