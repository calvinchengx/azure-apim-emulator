// Package certificate handles APIM client-certificate material.
package certificate

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"software.sslmate.com/src/go-pkcs12"
)

// ParsePKCS12 validates a PFX and returns its leaf certificate metadata.
func ParsePKCS12(data []byte, password string) (*x509.Certificate, string, error) {
	_, leaf, _, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, "", fmt.Errorf("decode PKCS#12 certificate: %w", err)
	}
	digest := sha1.Sum(leaf.Raw)
	return leaf, strings.ToUpper(hex.EncodeToString(digest[:])), nil
}

// TLSCertificate decodes a PFX into a certificate suitable for client authentication.
func TLSCertificate(data []byte, password string) (tls.Certificate, error) {
	privateKey, leaf, chain, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decode PKCS#12 certificate: %w", err)
	}
	result := tls.Certificate{PrivateKey: privateKey, Leaf: leaf, Certificate: [][]byte{leaf.Raw}}
	for _, certificate := range chain {
		result.Certificate = append(result.Certificate, certificate.Raw)
	}
	return result, nil
}
