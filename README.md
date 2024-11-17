# tzsp-layer
**TaZmen Sniffer Protocol (TZSP) layer for [github.com/google/gopacket](https://github.com/google/gopacket).**
 This package implements easy way to extract the final payload or intermediate protocol data from TZSP packet.

### About protocol
TZSP is encapsulation protocol for other protocols over UDP.
Сommonly used for transferring sniffed packets from routers (e.g. Mikrotik Packet Sniffer) and IDS software.

## Install
```bash
go get github.com/Yiivgeny/tzsp-layer
```

## Usage
Import this package
```go
import tzsp github.com/Yiivgeny/tzsp-layer
```

Decode packet data using the package layer
```go
packet := gopacket.NewPacket(buffer, tzsp.LayerTypeTZSP, gopacket.Default)

// Extract data from the final protocol
data := packet.ApplicationLayer().Payload()

// or extract a specific layer (e.g., TCP)
tcpPacket := packet.TransportLayer()
```

### Server example
Full example located in [example/server.go](example/server.go) and can be launched with `go run example/server.go`
