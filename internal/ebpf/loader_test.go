package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestDecodePacketEventMatchesBPFLayout(t *testing.T) {
	raw := make([]byte, 40) // C struct is padded to 40 bytes.
	binary.LittleEndian.PutUint64(raw[0:8], 123456)
	binary.LittleEndian.PutUint32(raw[8:12], 0x10203040)
	binary.LittleEndian.PutUint32(raw[12:16], 0x0164a8c0)
	binary.LittleEndian.PutUint32(raw[16:20], 0x0364a8c0)
	binary.LittleEndian.PutUint32(raw[20:24], 0x02003c0a)
	binary.LittleEndian.PutUint32(raw[24:28], 0x08080808)
	binary.LittleEndian.PutUint32(raw[28:32], 1400)
	raw[32] = DirectionDownlink
	raw[33] = 9

	event, ok := decodePacketEvent(raw)
	if !ok {
		t.Fatal("decodePacketEvent rejected a valid BPF event")
	}
	if event.Timestamp != 123456 ||
		event.TEID != 0x10203040 ||
		event.SrcIP != 0x0164a8c0 ||
		event.DstIP != 0x0364a8c0 ||
		event.InnerSrcIP != 0x02003c0a ||
		event.InnerDstIP != 0x08080808 ||
		event.PktLen != 1400 ||
		event.Direction != DirectionDownlink ||
		event.QFI != 9 {
		t.Fatalf("decoded event does not match BPF layout: %+v", event)
	}
}

func TestDecodePacketEventRejectsShortSample(t *testing.T) {
	if _, ok := decodePacketEvent(make([]byte, 35)); ok {
		t.Fatal("decodePacketEvent accepted a truncated sample")
	}
}

func TestDecodeDropEventMatchesBPFLayout(t *testing.T) {
	raw := make([]byte, 40)
	binary.LittleEndian.PutUint64(raw[0:8], 987654321)
	binary.LittleEndian.PutUint32(raw[8:12], 0x10203040)
	binary.LittleEndian.PutUint32(raw[12:16], 0x0100000a)
	binary.LittleEndian.PutUint32(raw[16:20], 0x08080808)
	binary.LittleEndian.PutUint32(raw[20:24], 128)
	binary.LittleEndian.PutUint16(raw[24:26], 49152)
	binary.LittleEndian.PutUint16(raw[26:28], 443)
	binary.LittleEndian.PutUint16(raw[28:30],
		FieldTEID|FieldSrcIP|FieldDstIP|FieldSrcPort|FieldDstPort)
	raw[30] = DropReasonNoPDR
	raw[31] = DirectionUplink
	raw[32] = 4
	raw[33] = 17
	raw[34] = OriginEncapRecv

	event, ok := decodeDropEvent(raw)
	if !ok {
		t.Fatal("decodeDropEvent rejected a valid BPF event")
	}
	if event.Timestamp != 987654321 ||
		event.TEID != 0x10203040 ||
		event.PktLen != 128 ||
		event.SrcPort != 49152 ||
		event.DstPort != 443 ||
		event.Reason != DropReasonNoPDR ||
		event.Direction != DirectionUplink ||
		event.Family != 4 ||
		event.L4Protocol != 17 ||
		event.Origin != OriginEncapRecv ||
		!event.HasField(FieldTEID) {
		t.Fatalf("decoded drop event does not match BPF layout: %+v", event)
	}
}

func TestDecodeDropEventRejectsShortSample(t *testing.T) {
	if _, ok := decodeDropEvent(make([]byte, 35)); ok {
		t.Fatal("decodeDropEvent accepted a truncated sample")
	}
}
