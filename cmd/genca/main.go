package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	// Generate a new P256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Fatalf("Failed to generate serial number: %v", err)
	}

	// Create CA certificate template
	caTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My CA"},
			CommonName:   "My CA Root",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 year validity
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// Create CA certificate
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create CA certificate: %v", err)
	}

	privKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Failed to marshal private key: %v", err)
	}
	// Encode private key to PEM
	privKeyPEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyDER,
	}
	if err := os.WriteFile("ca-key.pem", pem.EncodeToMemory(privKeyPEM), 0600); err != nil {
		log.Fatalf("Failed to write private key: %v", err)
	}

	// Encode certificate to PEM
	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	}
	if err := os.WriteFile("ca-cert.pem", pem.EncodeToMemory(certPEM), 0644); err != nil {
		log.Fatalf("Failed to write certificate: %v", err)
	}

	log.Println("Successfully generated CA certificate and private key")

}
