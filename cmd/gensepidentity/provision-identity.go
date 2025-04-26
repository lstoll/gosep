package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"time"

	"github.com/lstoll/gosep/internal/seidentity"
)

type ProvisionIdentityCmd struct {
	KeyLabel string `arg:"" optional:"" help:"Optional label for the key. Defaults to a timestamped value."`
}

func (c *ProvisionIdentityCmd) Run(g *Globals) error {
	keyLabel := c.KeyLabel
	if keyLabel == "" {
		keyLabel = fmt.Sprintf("com.github.lstoll.gosep.gensepidentity-%s", time.Now().Format("20060102150405"))
	}
	log.Printf("Using key label: %s", keyLabel)

	caCert, caKey, err := loadCA(g.CACertPath, g.CAKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load CA: %w", err)
	}

	csr := &x509.CertificateRequest{
		Subject: pkix.Name{
			Organization: []string{"My Org"},
			CommonName:   "Gen Sep Identity Client", // More specific common name
		},
	}

	csrPEM, err := seidentity.CreateKeyCSR(csr, keyLabel)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	certDER, err := signClientCert(csrPEM, caCert, caKey)
	if err != nil {
		return fmt.Errorf("failed to sign client cert: %w", err)
	}

	if err := seidentity.ProvisionKeychainIdentity(keyLabel, certDER); err != nil {
		return fmt.Errorf("failed to provision keychain identity: %w", err)
	}
	log.Printf("Successfully provisioned identity with label: %s", keyLabel)
	return nil
}
