package main

import (
	"encoding/binary"
)

const FIRSTFLAGMASK = 0x01
const LASTFLAGMASK = 0x02
const MAGIC = 0xA00A

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

func parseFlags(flags byte, pak *exfil) {
	pak.first = (flags&FIRSTFLAGMASK != 0)
	pak.last = (flags&LASTFLAGMASK != 0)
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

func parseExfil(b []byte) exfil {
	pak := exfil{false, false, "", nil}
	offset := 0
	parseFlags(b[0], &pak)
	offset++

	// read the file name
	if pak.first {
		filenameLength := int(b[offset])
		offset++
		pak.filename = string(b[offset : offset+filenameLength])
		offset += filenameLength
	}

	dataLength := int(binary.BigEndian.Uint16(b[offset : offset+2]))
	offset += 2
	pak.data = b[offset : offset+dataLength]

	return pak
}
