package ui

import (
	"image/color"
	"testing"
)

func TestMakeStatusIconShape(t *testing.T) {
	img := makeStatusIcon(colorConnected)

	b := img.Bounds()
	if b.Dx() != iconSize || b.Dy() != iconSize {
		t.Fatalf("图标尺寸 %dx%d，期望 %dx%d", b.Dx(), b.Dy(), iconSize, iconSize)
	}

	// 圆心应为主色且不透明。
	mid := img.NRGBAAt(iconSize/2, iconSize/2+4)
	if mid.A != 0xFF {
		t.Errorf("圆心应不透明，实际 alpha=%d", mid.A)
	}
	if mid.G < mid.R || mid.G < mid.B {
		t.Errorf("已连接图标圆心应偏绿，实际 %+v", mid)
	}

	// 四个角应完全透明，否则托盘里会显示成方块。
	for _, p := range [][2]int{{0, 0}, {iconSize - 1, 0}, {0, iconSize - 1}, {iconSize - 1, iconSize - 1}} {
		if a := img.NRGBAAt(p[0], p[1]).A; a != 0 {
			t.Errorf("角点 %v 应透明，实际 alpha=%d", p, a)
		}
	}
}

func TestStatusIconColorsDiffer(t *testing.T) {
	seen := map[color.NRGBA]string{}
	for name, c := range map[string]color.NRGBA{
		"connected":   colorConnected,
		"connecting":  colorConnecting,
		"blocked":     colorBlocked,
		"unprotected": colorUnprotected,
	} {
		mid := makeStatusIcon(c).NRGBAAt(iconSize/2, iconSize/2+4)
		if other, dup := seen[mid]; dup {
			t.Errorf("%s 与 %s 的图标颜色相同，用户无法区分状态", name, other)
		}
		seen[mid] = name
	}
}

func TestBlend(t *testing.T) {
	base := color.NRGBA{R: 0, G: 0, B: 0, A: 0xFF}
	if got := blend(base, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x00}); got != base {
		t.Errorf("alpha=0 时应保持原色，实际 %+v", got)
	}
	got := blend(base, color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF})
	if got.R != 0xFF || got.A != 0xFF {
		t.Errorf("alpha=255 时应完全覆盖，实际 %+v", got)
	}
}

func TestAppIcon(t *testing.T) {
	for _, size := range []int{16, 32, 48, 256} {
		img := AppIcon(size)
		if b := img.Bounds(); b.Dx() != size || b.Dy() != size {
			t.Fatalf("AppIcon(%d) 尺寸为 %dx%d", size, b.Dx(), b.Dy())
		}
		// 角点透明，圆心为底色。
		if a := img.NRGBAAt(0, 0).A; a != 0 {
			t.Errorf("size=%d 角点应透明，实际 alpha=%d", size, a)
		}
		if mid := img.NRGBAAt(size/2, size/2); mid != colorAppBase {
			t.Errorf("size=%d 圆心应为底色，实际 %+v", size, mid)
		}
	}

	// 过小的尺寸会被抬到 16，避免画出 0x0 图像。
	if b := AppIcon(4).Bounds(); b.Dx() != 16 {
		t.Errorf("AppIcon(4) 应抬到 16，实际 %d", b.Dx())
	}

	// 必须真的能看到白环，否则图标就是一个纯色圆。
	img := AppIcon(64)
	white := 0
	for y := 0; y < 64; y++ {
		for x := 0; x < 64; x++ {
			if img.NRGBAAt(x, y) == colorAppRing {
				white++
			}
		}
	}
	if white < 100 {
		t.Errorf("白环像素过少（%d），图标辨识度不足", white)
	}
}
