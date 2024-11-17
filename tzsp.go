package tzsp_layer

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var LayerTypeTZSP = gopacket.RegisterLayerType(1000, gopacket.LayerTypeMetadata{Name: "TZSP", Decoder: gopacket.DecodeFunc(decodeTZSP)})

type TagType uint8

const (
	TagTypePadding TagType = 0x00
	TagTagEnd      TagType = 0x01
	// More tags here
)

type Protocol uint16

const (
	ProtocolUnknown   Protocol = 0
	ProtocolEthernet  Protocol = 1
	ProtocolTokenRing Protocol = 2
	ProtocolSLIP      Protocol = 3
	ProtocolPPP       Protocol = 4
	ProtocolFDDI      Protocol = 5
	ProtocolRawUO     Protocol = 7
	ProtoIEEE80211    Protocol = 18
)

type TZSP struct {
	layers.BaseLayer

	Version       uint8
	Type          uint8
	EncapProtocol Protocol
	Tags          []Tag
}

type Tag struct {
	Type   TagType
	Length uint8
	Data   []byte
}

func (tzsp *TZSP) LayerType() gopacket.LayerType { return LayerTypeTZSP }

func (tzsp *TZSP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 4 {
		return errors.New("TZSP packet too small")
	}
	tzsp.Version = data[0]
	tzsp.Type = data[1]
	tzsp.EncapProtocol = Protocol(binary.BigEndian.Uint16(data[2:4]))

	if tzsp.Version != 1 {
		return fmt.Errorf("unsupported TZSP version: %d", tzsp.Version)
	}

	idx := 4
	for {
		if idx >= len(data) {
			return errors.New("unexpected end of packet while parsing tags")
		}
		tag := Tag{
			Type: TagType(data[idx]),
		}
		idx++

		if tag.Type == TagTagEnd {
			break
		}
		if tag.Type == TagTypePadding {
			continue
		}

		if idx >= len(data) {
			return errors.New("unexpected end of packet while parsing tag length")
		}
		tag.Length = data[idx]
		idx++

		if idx+int(tag.Length) > len(data) {
			return errors.New("unexpected end of packet while parsing tag data")
		}

		tag.Data = data[idx : idx+int(tag.Length)]
		idx += int(tag.Length)

		tzsp.Tags = append(tzsp.Tags, tag)
	}

	tzsp.BaseLayer = layers.BaseLayer{
		Contents: data[:idx],
		Payload:  data[idx:],
	}

	return nil
}

func (tzsp *TZSP) NextLayerType() gopacket.LayerType {
	switch tzsp.EncapProtocol {
	case ProtocolUnknown:
		return gopacket.LayerTypeDecodeFailure
	case ProtocolEthernet:
		return layers.LayerTypeEthernet
	default:
		return gopacket.LayerTypePayload
	}

}

func decodeTZSP(data []byte, p gopacket.PacketBuilder) error {
	tzsp := &TZSP{}
	err := tzsp.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(tzsp)

	return p.NextDecoder(tzsp.NextLayerType())
}
