package main

import (
	"log"

	"github.com/lstoll/osxsecure/keychain"
)

func main() {
	// k, err := keychain.CreateKey()
	// if err != nil {
	// 	log.Fatalf("failed: %v", err)
	// }
	// k.Close()
	// log.Print("done")

	// if err := keychain.CreateKey(); err != nil {
	// 	log.Fatalf("create key failed: %v", err)
	// }
	if err := keychain.GetKey(); err != nil {
		log.Fatalf("get key failed: %v", err)
	}
	log.Print("done")
}
