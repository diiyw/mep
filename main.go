package main

import (
	"github.com/diiyw/mep/socks"
	"os"
)

func main() {
	var port = ":1080"
	if len(os.Args) >= 2 {
		port = os.Args[1]
	}
	socks.Listen(port)
}
