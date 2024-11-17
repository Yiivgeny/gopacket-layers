package main

import (
	"log"
	"net"

	"github.com/google/gopacket"

	tzsp "github.com/Yiivgeny/tzsp-layer"
)

func main() {
	addr := net.UDPAddr{
		Port: 37008,
		IP:   net.IPv4zero,
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Error setting up UDP listener: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 65535)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("Error reading from UDP: %v", err)
			continue
		}
		log.Printf("Received packet from %s, size %d bytes", remoteAddr, n)

		packet := gopacket.NewPacket(buf[:n], tzsp.LayerTypeTZSP, gopacket.Default)
		if payload := packet.ApplicationLayer(); payload != nil {
			log.Printf("TZSP parsed with payload size: %d", len(payload.Payload()))
		}
	}
}
