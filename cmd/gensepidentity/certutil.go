package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"time"
)

// createOrLoadCA generates a new CA key/cert or loads existing ones.
func loadCA(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	fmt.Println("Loading existing CA cert and key...")
	// Load existing key
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA key file: %w", err)
	}
	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA key PEM")
	}
	caPrivKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	// Load existing cert
	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA cert file: %w", err)
	}
	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}
	fmt.Println("CA loaded successfully.")
	return caCert, caPrivKey, nil
}

// signClientCert signs the CSR with the CA, returning the cert der bytes.
func signClientCert(csrPEMBytes []byte, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, error) {
	fmt.Println("Decoding CSR PEM...")
	block, _ := pem.Decode(csrPEMBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CSR PEM block")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid PEM block type: expected 'CERTIFICATE REQUEST', got '%s'", block.Type)
	}

	fmt.Println("Parsing CSR DER...")
	csr, err := x509.ParseCertificateRequest(block.Bytes) // Parse the DER bytes from the block
	if err != nil {
		// Add more context to the error
		log.Printf("Raw DER bytes being parsed (first 60): %x", block.Bytes[:min(60, len(block.Bytes))])
		return nil, fmt.Errorf("failed to parse CSR DER: %w", err)
	}

	fmt.Println("Verifying CSR signature...")
	// Verify CSR signature using the *public* key from the CSR.
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}
	fmt.Println("CSR signature verified successfully.")

	// Create client certificate template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number for client cert: %w", err)
	}

	clientTemplate := x509.Certificate{
		// We don't copy Signature/SigAlg from CSR, we generate a new one signed by CA
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm, // Use algorithm from CSR
		PublicKey:          csr.PublicKey,          // Use public key from CSR

		SerialNumber: serialNumber,
		Issuer:       caCert.Subject,                                 // Issuer is the CA
		Subject:      csr.Subject,                                    // Subject taken from CSR
		NotBefore:    time.Now().Add(-1 * time.Minute),               // Allow for slight clock skew
		NotAfter:     time.Now().AddDate(0, 6, 0),                    // 6 months validity
		KeyUsage:     x509.KeyUsageDigitalSignature,                  // Essential for TLS signing
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // *** IMPORTANT for mTLS ***
		// BasicConstraintsValid: false, // Client certs typically aren't CAs
	}

	fmt.Println("Signing client certificate with CA...")
	// Sign the client certificate using the CA's private key and the CSR's public key
	clientCertBytes, err := x509.CreateCertificate(rand.Reader, &clientTemplate, caCert, csr.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create client certificate: %w", err)
	}

	fmt.Println("Client certificate created.")
	return clientCertBytes, nil
}

// Helper function needed if min isn't already defined globally
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
