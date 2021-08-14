package main

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	k, err := keychain.GetKey(tag)
	if err != nil {
		log.Fatalf("get key failed: %v", err)
	}
	log.Print("get worked")

	pub := k.Public().(*ecdsa.PublicKey)

	x509EncodedPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		log.Fatal(err)
	}
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})
	log.Print("pub key:")
	fmt.Println(string(pemEncodedPub))

	if err := keychain.DeleteKey(tag); err != nil {
		log.Fatalf("delete key failed: %v", err)
	}
	log.Print("done")
}
