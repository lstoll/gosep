package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"time"

	"github.com/lstoll/gosep/internal/seidentity" // Assuming this is the correct path
)

// MTLSConnectCmd defines the command for connecting to a remote host using mTLS.
type MTLSConnectCmd struct {
	Host          string `arg:"" required:"" help:"Remote host address (e.g., 'https://hostname:port' or 'hostname:port')."`
	IdentityLabel string `flag:"" optional:"" short:"l" help:"Label of the specific identity to use (defaults to the first found)."`
	Path          string `flag:"" optional:"" default:"/" help:"Path to request via HTTP GET after connecting."`
	Insecure      bool   `flag:"" short:"k" help:"Skip verification of the server's certificate chain."`
	// CA cert path can be inherited from Globals or specified if needed,
	// but for simplicity, we'll rely on the global or insecure flag for now.
}

// Run executes the mTLS connection command.
func (cmd *MTLSConnectCmd) Run(globals *Globals) error {
	log.Println("Attempting to list keychain identities...")
	identities, err := seidentity.ListKeychainIdentities()
	if err != nil {
		return fmt.Errorf("failed to list keychain identities: %w", err)
	}

	if len(identities) == 0 {
		return fmt.Errorf("no keychain identities found. Provision an identity first")
	}

	log.Printf("Found %d identities.", len(identities))

	var selectedIdentity *seidentity.KeychainIdentityInfo

	// Select identity
	if cmd.IdentityLabel != "" {
		log.Printf("Searching for identity with label: %s", cmd.IdentityLabel)
		found := false
		for i := range identities {
			if identities[i].Label == cmd.IdentityLabel {
				selectedIdentity = &identities[i]
				found = true
				log.Printf("Found matching identity.")
				break
			}
		}
		if !found {
			return fmt.Errorf("no identity found with label: %s", cmd.IdentityLabel)
		}
	} else {
		log.Println("No specific label provided, using the first identity found.")
		selectedIdentity = &identities[0]
	}

	log.Printf("Using identity with label: %s (Subject: %s)", selectedIdentity.Label, selectedIdentity.Certificate.Subject)

	// Prepare TLS Config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: [][]byte{selectedIdentity.Certificate.Raw},
				PrivateKey:  selectedIdentity.Signer, // Use the Secure Enclave signer
				Leaf:        selectedIdentity.Certificate,
			},
		},
		InsecureSkipVerify: cmd.Insecure,
		MinVersion:         tls.VersionTLS12, // Set a reasonable minimum TLS version
	}

	// Configure Root CA pool for server verification, unless skipping
	if !cmd.Insecure {
		log.Printf("Loading CA certificate from: %s", globals.CACertPath)
		caCertPEM, err := os.ReadFile(globals.CACertPath)
		if err != nil {
			return fmt.Errorf("failed to read CA certificate file '%s': %w", globals.CACertPath, err)
		}
		rootCAs := x509.NewCertPool()
		if !rootCAs.AppendCertsFromPEM(caCertPEM) {
			return fmt.Errorf("failed to append CA certificate from '%s' to pool", globals.CACertPath)
		}
		tlsConfig.RootCAs = rootCAs
		log.Println("CA certificate loaded successfully.")
	} else {
		log.Println("Skipping server certificate verification (InsecureSkipVerify=true).")
	}

	// Attempt TLS connection
	log.Printf("Attempting mTLS connection to %s...", cmd.Host)
	conn, err := tls.Dial("tcp", cmd.Host, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to establish mTLS connection to %s: %w", cmd.Host, err)
	}
	defer conn.Close()

	log.Printf("Successfully connected to %s using mTLS!", cmd.Host)
	log.Printf("Server certificate: Subject=%s, Issuer=%s", conn.ConnectionState().PeerCertificates[0].Subject, conn.ConnectionState().PeerCertificates[0].Issuer)
	log.Printf("TLS Version: %s", tlsVersionString(conn.ConnectionState().Version))
	log.Printf("Cipher Suite: %s", tls.CipherSuiteName(conn.ConnectionState().CipherSuite))

	// --- Perform HTTP GET request ---
	log.Printf("Performing HTTP GET request to path: %s", cmd.Path)

	// Create an http.Client that uses the established TLS connection
	// Note: The standard http.Transport uses DialTLSContext, which wants to
	// establish a *new* connection. We already have one.
	// We can reuse the tls.Config for hostname verification etc.,
	// but tell the client to use our existing net.Conn.
	// A simple way for a single request is using http.NewRequest and client.Do
	// with a transport configured *not* to dial again implicitly.

	// Construct the URL, assuming https if not specified.
	url := cmd.Host + cmd.Path
	if url[0] == ':' { // Handle case like :443/
		return fmt.Errorf("invalid host format, should include hostname: %s", cmd.Host)
	}
	if !regexp.MustCompile(`^https?://`).MatchString(url) {
		url = "https://" + url
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Create a custom transport that uses our specific connection.
	// This is a simplified approach for a single connection.
	// For more complex scenarios (connection pooling, reuse), a more robust transport is needed.
	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			// Ensure we're trying to use the connection for the correct host
			if addr != cmd.Host {
				return nil, fmt.Errorf("http transport asked to dial different address (%s) than initial connection (%s)", addr, cmd.Host)
			}
			// Return the already established connection
			// Note: This connection will be closed by the client.Do call OR our defer conn.Close()
			// We return 'conn' here, but subsequent calls to this DialTLS would fail
			// if the client tried to reuse the transport for another host.
			// Also, connection state (like TLS session) might not be managed as efficiently as default transport.
			return conn, nil
		},
		TLSClientConfig: tlsConfig, // Reuse our TLS config for verification settings
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second, // Add a timeout for the HTTP request
	}

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		// conn is likely closed by the transport error or our defer, no need to close again explicitly here.
		return fmt.Errorf("failed to perform HTTP GET request: %w", err)
	}
	defer resp.Body.Close()

	log.Printf("HTTP Response Status: %s", resp.Status)

	// Read and print the response body (optional)
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Warning: Failed to read response body: %v", err)
	} else {
		log.Printf("HTTP Response Body:\n%s", string(bodyBytes))
	}

	// conn.Close() is handled by the defer earlier
	log.Println("HTTP request finished, closing connection.")
	return nil
}

// Helper to get TLS version string
func tlsVersionString(ver uint16) string {
	switch ver {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", ver)
	}
}
