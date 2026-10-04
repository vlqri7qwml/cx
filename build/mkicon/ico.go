package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/png"
	"io"
)

// writeICO 写出一个多尺寸的 .ico 文件。
//
// 每一帧直接以 PNG 存放（Vista 起的 Windows 都支持 PNG 压缩的图标帧），
// 这样不必手写 BMP + AND 掩码，也能保留 alpha 通道。
func writeICO(w io.Writer, images []image.Image) error {
	if len(images) == 0 {
		return fmt.Errorf("至少需要一帧图像")
	}
	if len(images) > 255 {
		return fmt.Errorf("图标帧数过多: %d", len(images))
	}

	payloads := make([][]byte, len(images))
	for i, img := range images {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return err
		}
		payloads[i] = buf.Bytes()
	}

	// ICONDIR: reserved(2) + type(2) + count(2)
	const dirSize = 6
	const entrySize = 16

	if err := binary.Write(w, binary.LittleEndian, [3]uint16{0, 1, uint16(len(images))}); err != nil {
		return err
	}

	offset := uint32(dirSize + entrySize*len(images))
	for i, img := range images {
		b := img.Bounds()
		// 256 在目录项里记作 0。
		dim := func(v int) uint8 {
			if v >= 256 {
				return 0
			}
			return uint8(v)
		}
		entry := struct {
			Width, Height, Colors, Reserved uint8
			Planes, BitCount                uint16
			BytesInRes, Offset              uint32
		}{
			Width:      dim(b.Dx()),
			Height:     dim(b.Dy()),
			Planes:     1,
			BitCount:   32,
			BytesInRes: uint32(len(payloads[i])),
			Offset:     offset,
		}
		if err := binary.Write(w, binary.LittleEndian, entry); err != nil {
			return err
		}
		offset += uint32(len(payloads[i]))
	}

	for _, p := range payloads {
		if _, err := w.Write(p); err != nil {
			return err
		}
	}
	return nil
}
