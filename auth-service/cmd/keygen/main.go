package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(path string, b []byte, mode os.FileMode) {
	must(os.WriteFile(path, b, mode))
	fmt.Println("wrote", path)
}

func genRS(outPriv, outPub string) {
	// 2048-bit is fine; 3072 for longer-term
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	// Private (PKCS#1)
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	write(outPriv, priv, 0600)
	// Public (SPKI)
	pubDer, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	must(err)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	write(outPub, pub, 0644)
}

func genEd(outPriv, outPub string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must(err)
	// Private (PKCS#8)
	privDer, err := x509.MarshalPKCS8PrivateKey(priv)
	must(err)
	privPem := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDer})
	write(outPriv, privPem, 0600)
	// Public (SPKI)
	pubDer, err := x509.MarshalPKIXPublicKey(pub)
	must(err)
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDer})
	write(outPub, pubPem, 0644)
}

func main() {
	alg := flag.String("alg", "rs", "rs or ed")
	dir := flag.String("out", "/secrets", "output directory")
	kid := flag.String("kid", "kid-auto", "filename stem")
	flag.Parse()

	_ = os.MkdirAll(*dir, 0o755)
	priv := fmt.Sprintf("%s/%s.key", *dir, *kid)
	pub := fmt.Sprintf("%s/%s.pub", *dir, *kid)

	switch *alg {
	case "rs":
		genRS(priv, pub)
	case "ed":
		genEd(priv, pub)
	default:
		panic("alg must be rs or ed")
	}
}
