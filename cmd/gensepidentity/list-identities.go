package main

import (
	"fmt"
	"log"

	"github.com/lstoll/gosep/internal/seidentity"
)

type ListIdentitiesCmd struct{}

func (c *ListIdentitiesCmd) Run(g *Globals) error {
	// TODO: Implement listing keychain identities
	secidentities, err := seidentity.ListKeychainIdentities()
	if err != nil {
		return fmt.Errorf("failed to list SE identities: %w", err)
	}
	for _, identity := range secidentities {
		log.Printf("Identity: %v", identity)
	}
	return nil
}
