package main

import (
	"log"
)

const webPort = "80"

type Config struct {
}

func main() {
	log.Println("Starting authentication service on port:", webPort)
}
