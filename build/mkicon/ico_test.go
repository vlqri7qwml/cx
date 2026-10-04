package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"testing"

	"github.com/vlqri7qwml/cx/internal/ui"
)

func TestWriteICO(t *testing.T) {
	sizes := []int{16, 32, 256}
	images := make([]image.Image, 0, len(sizes))
	for _, s := range sizes {
		images = append(images, ui.AppIcon(s))
	}

	var buf bytes.Buffer
	if err := writeICO(&buf, images); err != nil {
		t.Fatalf("writeICO: %v", err)
	}
	b := buf.Bytes()

	if len(b) < 6+16*len(sizes) {
		t.Fatalf("输出过短: %d 字节", len(b))
	}
	if got := binary.LittleEndian.Uint16(b[0:2]); got != 0 {
		t.Errorf("reserved = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(b[2:4]); got != 1 {
		t.Errorf("type = %d, want 1 (ICON)", got)
	}
	if got := int(binary.LittleEndian.Uint16(b[4:6])); got != len(sizes) {
		t.Fatalf("count = %d, want %d", got, len(sizes))
	}

	for i, want := range sizes {
		off := 6 + 16*i
		gotW := int(b[off])
		// 256 在目录项里记作 0。
		expect := want
		if want >= 256 {
			expect = 0
		}
		if gotW != expect {
			t.Errorf("第 %d 帧宽度字段 = %d, want %d", i, gotW, expect)
		}
		if bits := binary.LittleEndian.Uint16(b[off+6 : off+8]); bits != 32 {
			t.Errorf("第 %d 帧位深 = %d, want 32", i, bits)
		}
		length := binary.LittleEndian.Uint32(b[off+8 : off+12])
		offset := binary.LittleEndian.Uint32(b[off+12 : off+16])
		if int(offset+length) > len(b) {
			t.Fatalf("第 %d 帧越界: offset=%d length=%d total=%d", i, offset, length, len(b))
		}
		// 每一帧都应是合法 PNG。
		if got := b[offset : offset+8]; !bytes.Equal(got, []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}) {
			t.Errorf("第 %d 帧不是 PNG: % x", i, got)
		}
	}
}

func TestWriteICORejectsEmpty(t *testing.T) {
	if err := writeICO(&bytes.Buffer{}, nil); err == nil {
		t.Fatal("空输入应报错")
	}
}
