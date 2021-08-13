package main

import (
	"github.com/lstoll/osxsecure/keychain"
)

func main() {
	// k, err := keychain.CreateKey()
	// if err != nil {
	// 	log.Fatalf("failed: %v", err)
	// }
	// k.Close()
	// log.Print("done")

	keychain.TesterFunction()
}
