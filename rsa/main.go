package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {

	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var plainText, encrypted, decrypted, label []byte
	var err error

	plainText = []byte("Plain text message to be encrypted")

	//Generate Private Key
	if privateKey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		log.Fatal(err)
	}
	fmt.Println(privateKey)

	// Precompute some calculations -- Calculations that speed up private key operations in the future
	privateKey.Precompute()

	//Validate Private Key -- Sanity checks on the key
	if err = privateKey.Validate(); err != nil {
		log.Fatal(err)
	}

	//Public key address (of an RSA key)
	publicKey = &privateKey.PublicKey

	encrypted = encryptOaep(publicKey, plainText, label)
	decrypted = decryptOaep(privateKey, encrypted, label)

	fmt.Printf("OAEP Encrypted [%s] to \n[%x]\n", string(plainText), encrypted)
	fmt.Printf("OAEP Decrypted [%x] to \n[%s]\n", encrypted, decrypted)

	// To use existing private key (Skipping the GenerateKey, Precompute, Validation steps shown above)
	// This reads pem file and retrieves the public, private key needed to encrypt data
	useExsitingKeys()

}

func useExsitingKeys() {

	var pemFilePath string
	var err error
	var block *pem.Block
	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey
	var pemData, label []byte

	plainText := []byte("Plain text message to be encrypted")

	// A PEM file can contain a Private key among others (Public certificate, Intermidiate Certificate, Root certificate, ...)
	pemFilePath = "/path/to/pem/file"
	if pemData, err = ioutil.ReadFile(pemFilePath); err != nil {
		log.Fatalf("Error reading pem file: %s", err)
	}

	//Package pem implements the PEM data encoding, most commonly used in TLS keys and certificates.
	//Decode will find the next PEM formatted block (certificate, private key etc) in the input.
	//Expected Block type "RSA PRIVATE KEY"
	//http://golang.org/pkg/encoding/pem/
	if block, _ = pem.Decode(pemData); block == nil || block.Type != "RSA PRIVATE KEY" {
		log.Fatal("No valid PEM data found")
	}

	//x509 parses X.509-encoded keys and certificates.
	//ParsePKCS1PrivateKey returns an RSA private key from its ASN.1 PKCS#1 DER encoded form.
	if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		log.Fatalf("Private key can't be decoded: %s", err)
	}

	publicKey = &privateKey.PublicKey

	encrypted := encryptOaep(publicKey, plainText, label)
	decrypted := decryptOaep(privateKey, encrypted, label)

	fmt.Printf("OAEP Encrypted [%s] to \n[%x]\n", string(plainText), encrypted)
	fmt.Printf("OAEP Decrypted [%x] to \n[%s]\n", encrypted, decrypted)

	return
}

// encryptOaep executes rsa EncryptOAEP
func encryptOaep(publicKey *rsa.PublicKey, plainText, label []byte) (encrypted []byte) {
	var err error
	md5Hash := md5.New()
	if encrypted, err = rsa.EncryptOAEP(md5Hash, rand.Reader, publicKey, plainText, label); err != nil {
		log.Fatal(err)
	}
	return
}

// decryptOaep executes rsa DecryptOAEP
func decryptOaep(privateKey *rsa.PrivateKey, encrypted, label []byte) (decrypted []byte) {
	var err error
	md5Hash := md5.New()
	if decrypted, err = rsa.DecryptOAEP(md5Hash, rand.Reader, privateKey, encrypted, label); err != nil {
		log.Fatal(err)
	}
	return
}
