package main

import (
	"log"

	"github.com/lstoll/gosep/keychain"
)

func main() {
	// k, err := keychain.CreateKey()
	// if err != nil {
	// 	log.Fatalf("failed: %v", err)
	// }
	// k.Close()
	// log.Print("done")

	const tag = "li.lds.gosep.testkey1"

	if _, err := keychain.CreateKey(tag); err != nil {
		log.Printf("create key failed: %v", err)
	}
	log.Print("create worked")
	if _, err := keychain.GetKey(tag); err != nil {
		log.Fatalf("get key failed: %v", err)
	}
	log.Print("get worked")
	if err := keychain.DeleteKey(tag); err != nil {
		log.Fatalf("delete key failed: %v", err)
	}
	log.Print("done")
}
