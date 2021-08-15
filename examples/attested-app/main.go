package main

import (
	"log"

	"github.com/lstoll/gosep/appattest"
)

func main() {
	log.Printf("supported: %t", appattest.Supported())
}
