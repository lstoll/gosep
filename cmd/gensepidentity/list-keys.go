package main

import (
	"fmt"
	"log"

	"github.com/lstoll/gosep/internal/seidentity"
)

type ListKeysCmd struct{}

func (c *ListKeysCmd) Run(g *Globals) error {
	keys, err := seidentity.ListSecureEnclaveKeyInfos()
	if err != nil {
		return fmt.Errorf("failed to list SE keys: %w", err)
	}

	for _, key := range keys {
		log.Printf("Key: %v", key)
	}
	return nil
}
