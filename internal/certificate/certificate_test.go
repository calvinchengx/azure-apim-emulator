package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

func TestParsePKCS12(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "client.test"}, NotBefore: time.Unix(1, 0), NotAfter: time.Unix(4102444800, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pfx, err := pkcs12.Modern.Encode(key, leaf, nil, "password")
	if err != nil {
		t.Fatal(err)
	}
	parsed, thumbprint, err := ParsePKCS12(pfx, "password")
	if err != nil || parsed.Subject.CommonName != "client.test" || len(thumbprint) != 40 {
		t.Fatalf("parsed = %+v %q, %v", parsed, thumbprint, err)
	}
	if _, _, err := ParsePKCS12(pfx, "wrong"); err == nil {
		t.Fatal("wrong password should fail")
	}
	tlsCertificate, err := TLSCertificate(pfx, "password")
	if err != nil || tlsCertificate.Leaf == nil || len(tlsCertificate.Certificate) != 1 {
		t.Fatalf("TLS certificate = %+v, %v", tlsCertificate, err)
	}
	if _, err := TLSCertificate(pfx, "wrong"); err == nil {
		t.Fatal("wrong TLS certificate password should fail")
	}
	chainedPFX, err := pkcs12.Modern.Encode(key, leaf, []*x509.Certificate{leaf}, "password")
	if err != nil {
		t.Fatal(err)
	}
	if chained, err := TLSCertificate(chainedPFX, "password"); err != nil || len(chained.Certificate) != 2 {
		t.Fatalf("certificate chain = %+v, %v", chained, err)
	}
}
