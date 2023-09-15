package main

import (
    "fmt"
    "flag"
    "os"
    "log"
)

/*
* Since ICMP limits the data field size, the contents of the file will be sent
* in packets instead. The data packet will contain a small header for the first
* packet and for each subsequent packet.
*
* [FIRST PACKET]
* The first byte is for a magic number that defines this protocol.
* The next byte contains flags pertaining to the protocol.
* The next byte is for filename length (256 chars is typically a max name size)
* Next field contains the previous fields amount of bytes for the filename.
* The next 2 bytes hold the length of file data
* The remaining bytes are part of the file data
*
* [SEQUENCE PACKETS]
* The first byte is for a magic number that defines this protocol.
* The next byte contains flags pertaining to the protocol.
* The next 2 bytes hold the length of file data
* The remaining bytes are part of the file data
*
* [FLAGS]
* In order of bit 0 to bit 7:
* f -> beginning of file data
* e -> end of file data
*
* [MAGIC NUMBER]
* 0b10101010
* 0xAA
*
*/

func main() {
    var file = flag.String("f", "", "the file to exfiltrate via ICMP")
   // var ipv6 = flag.Bool("6", false, "enables the use of IPv6 instead of IPv4")

    flag.Parse()


    // Open the local file
    f, err := os.Open(*file)
    if err != nil {
        log.Fatalln(err)
    }
    defer f.Close()

    fmt.Printf("test\n")
    return
}