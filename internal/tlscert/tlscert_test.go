package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadEphemeralAndPersisted(t *testing.T) {
	ephemeral, err := Load("")
	if err != nil || len(ephemeral.Certificate) == 0 {
		t.Fatalf("ephemeral Load() = %v", err)
	}
	leaf, err := x509.ParseCertificate(ephemeral.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"localhost", "management.azure.localhost", "service.azure-api.localhost"} {
		if err := leaf.VerifyHostname(host); err != nil {
			t.Errorf("certificate does not cover %s: %v", host, err)
		}
	}

	dir := t.TempDir()
	first, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificate[0]) != string(second.Certificate[0]) {
		t.Fatal("persisted certificate changed")
	}
	for _, name := range []string{"cert.pem", "key.pem"} {
		if _, err := os.Stat(filepath.Join(dir, "tls", name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestGenerateFailures(t *testing.T) {
	want := errors.New("crypto failed")
	oldKey, oldSerial, oldCreate, oldMarshal := generateKey, generateSerial, createCertificate, marshalPrivateKey
	t.Cleanup(func() {
		generateKey = oldKey
		generateSerial = oldSerial
		createCertificate = oldCreate
		marshalPrivateKey = oldMarshal
	})
	reset := func() {
		generateKey = oldKey
		generateSerial = oldSerial
		createCertificate = oldCreate
		marshalPrivateKey = oldMarshal
	}

	generateKey = func(elliptic.Curve, io.Reader) (*ecdsa.PrivateKey, error) { return nil, want }
	if _, _, err := generate(); !errors.Is(err, want) {
		t.Fatalf("key error = %v", err)
	}
	if _, err := Load(""); !errors.Is(err, want) {
		t.Fatalf("ephemeral Load error = %v", err)
	}
	if _, err := Load(t.TempDir()); !errors.Is(err, want) {
		t.Fatalf("persisted Load error = %v", err)
	}
	reset()

	generateSerial = func(io.Reader, *big.Int) (*big.Int, error) { return nil, want }
	if _, _, err := generate(); !errors.Is(err, want) {
		t.Fatalf("serial error = %v", err)
	}
	reset()

	createCertificate = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) {
		return nil, want
	}
	if _, _, err := generate(); !errors.Is(err, want) {
		t.Fatalf("certificate error = %v", err)
	}
	reset()

	marshalPrivateKey = func(*ecdsa.PrivateKey) ([]byte, error) { return nil, want }
	if _, _, err := generate(); !errors.Is(err, want) {
		t.Fatalf("marshal error = %v", err)
	}
}

func TestLoadFilesystemFailures(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file); err == nil {
		t.Fatal("MkdirAll failure succeeded")
	}

	certDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(certDir, "tls", "cert.pem"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(certDir); err == nil {
		t.Fatal("certificate write failure succeeded")
	}

	keyDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(keyDir, "tls", "key.pem"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(keyDir); err == nil {
		t.Fatal("key write failure succeeded")
	}

}
