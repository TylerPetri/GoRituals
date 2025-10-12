package httpapi

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// LoadEd25519PrivateKeyPEM expects PKCS#8 "PRIVATE KEY" (unencrypted).
func LoadEd25519PrivateKeyPEM(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported PEM type %q (want PKCS#8 PRIVATE KEY)", block.Type)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}
	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("pkcs8 is not ed25519 private key")
	}
	return priv, nil
}

// LoadEd25519PublicKeyPEM expects X.509 SPKI "PUBLIC KEY".
func LoadEd25519PublicKeyPEM(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("unsupported PEM type %q (want PUBLIC KEY)", block.Type)
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse spki: %w", err)
	}
	pub, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("public key is not ed25519")
	}
	return pub, nil
}
