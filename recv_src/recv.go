package main

import (
	"flag"
	"fmt"

	"golang.org/x/net/icmp"
)

func main() {
	var help = flag.Bool("h", false, "show help.")
	var host = flag.String("l", "127.0.0.1", "the location ip to read from")

	flag.Parse()

	if *help {
		flag.PrintDefaults()
		return
	}
	b := make([]byte, 1600)
	socket, _ := icmp.ListenPacket("ip4:icmp", *host)
	for {
		if bytesRead, source, err := socket.ReadFrom(b); err != nil && source != nil && bytesRead != 0 {
			fmt.Printf("got: %x\n", b)
		}
	}
}
