package main

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"
	"time"

	"github.com/lstoll/gosep/internal/seidentity" // Assuming this is the correct path
)

// BenchSignCmd defines the command for benchmarking signing operations.
type BenchSignCmd struct {
	Iterations    int    `flag:"" optional:"" default:"20" help:"Number of signing iterations to perform."`
	IdentityLabel string `flag:"" optional:"" short:"l" help:"Label of the specific identity to use (defaults to the first found)."`
	DataSize      int    `flag:"" optional:"" default:"32" help:"Size of the random data payload to sign in each iteration (bytes)."`
}

// Run executes the bench-sign command.
func (cmd *BenchSignCmd) Run(globals *Globals) error {
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
	log.Printf("Starting benchmark: %d iterations, %d byte payload.", cmd.Iterations, cmd.DataSize)

	// Prepare signer and options
	signer := selectedIdentity.Signer
	// For ECDSA keys (common with Secure Enclave), we usually sign the hash of the data.
	// The seidentity Signer likely expects the *hash* as input.
	hashFunc := crypto.SHA256

	var totalDuration time.Duration
	var signatures [][]byte // Store signatures to prevent optimization issues? Maybe not needed.

	// Prepare data outside the loop if it's constant, or inside if it should vary
	payload := make([]byte, cmd.DataSize)
	if _, err := rand.Read(payload); err != nil {
		return fmt.Errorf("failed to generate random payload: %w", err)
	}
	digest := sha256.Sum256(payload)

	startTime := time.Now()

	for i := 0; i < cmd.Iterations; i++ {
		// If payload should change per iteration, generate and hash here.
		// For benchmarking the signing op itself, using the same digest is fine.
		// digest := sha256.Sum256(payload) // Example if hashing inside loop

		iterStart := time.Now()
		signature, err := signer.Sign(rand.Reader, digest[:], hashFunc)
		iterDuration := time.Since(iterStart)

		if err != nil {
			// Maybe log the error and continue, or stop the benchmark? Stop seems safer.
			return fmt.Errorf("signing failed on iteration %d: %w", i+1, err)
		}
		signatures = append(signatures, signature) // Keep track if needed
		totalDuration += iterDuration
		// Optional: Log per-iteration time
		// log.Printf("Iteration %d took %v", i+1, iterDuration)
	}

	endTime := time.Now()
	overallDuration := endTime.Sub(startTime) // Can be slightly different from summed durations

	log.Println("------------------------------------")
	log.Println("Benchmark Results")
	log.Println("------------------------------------")
	log.Printf("Total iterations: %d", cmd.Iterations)
	log.Printf("Payload size: %d bytes (hashed with SHA256)", cmd.DataSize)
	log.Printf("Identity used: %s", selectedIdentity.Label)
	log.Printf("Total time (sum of iterations): %v", totalDuration)
	log.Printf("Total time (overall wall clock): %v", overallDuration)
	if cmd.Iterations > 0 {
		avgDuration := totalDuration / time.Duration(cmd.Iterations)
		log.Printf("Average time per signing operation: %v", avgDuration)
		opsPerSecond := float64(cmd.Iterations) / overallDuration.Seconds()
		log.Printf("Operations per second (approx): %.2f", opsPerSecond)
	}
	log.Println("------------------------------------")

	// Optional: Verify one of the signatures? Could add overhead.
	// pubKey := selectedIdentity.Certificate.PublicKey
	// if ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey); ok {
	// 	if !ecdsa.VerifyASN1(ecdsaPubKey, digest[:], signatures[0]) {
	// 		log.Println("Warning: Failed to verify the first signature.")
	// 	} else {
	// 		log.Println("Successfully verified the first signature.")
	// 	}
	// } else {
	//  log.Println("Cannot verify signature: Public key is not ECDSA.")
	// }

	return nil
}
