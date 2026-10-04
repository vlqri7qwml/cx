package ui

import (
	"image"
	"image/color"
	"math"
)

// 托盘图标用到的状态色。
var (
	colorConnected    = color.NRGBA{R: 0x2E, G: 0xA0, B: 0x43, A: 0xFF} // 绿：已连接
	colorConnecting   = color.NRGBA{R: 0xE0, G: 0xA0, B: 0x12, A: 0xFF} // 黄：连接中
	colorBlocked      = color.NRGBA{R: 0xD2, G: 0x3B, B: 0x2E, A: 0xFF} // 红：断网保护中
	colorUnprotected  = color.NRGBA{R: 0x80, G: 0x80, B: 0x80, A: 0xFF} // 灰：保护未启动
	colorIconOutline  = color.NRGBA{R: 0x1A, G: 0x1A, B: 0x1A, A: 0xB0}
	colorIconHighlite = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0x55}
)

// iconSize 是生成的图标边长。托盘会自行缩放，32 足够清晰。
const iconSize = 32

// makeStatusIcon 画一个指定颜色的圆形状态图标。
//
// 直接在运行期画图标，省掉了往仓库里塞 .ico 资源、
// 以及资源 ID 与代码不同步的麻烦。
func makeStatusIcon(c color.NRGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, iconSize, iconSize))

	const (
		center = (iconSize - 1) / 2.0
		radius = iconSize/2.0 - 1.5
		// ring 是描边宽度。
		ring = 1.6
	)

	for y := 0; y < iconSize; y++ {
		for x := 0; x < iconSize; x++ {
			dx := float64(x) - center
			dy := float64(y) - center
			d := math.Sqrt(dx*dx + dy*dy)

			switch {
			case d <= radius-ring:
				// 内部：主色，上半部略微提亮，让图标有一点立体感。
				px := c
				if dy < -radius/3 {
					px = blend(c, colorIconHighlite)
				}
				img.SetNRGBA(x, y, px)
			case d <= radius:
				img.SetNRGBA(x, y, blend(c, colorIconOutline))
			case d <= radius+1:
				// 边缘做一像素的渐隐，避免锯齿太硬。
				a := uint8(math.Max(0, (radius+1-d))*255) / 1
				px := colorIconOutline
				px.A = uint8(float64(px.A) * float64(a) / 255)
				img.SetNRGBA(x, y, px)
			}
		}
	}
	return img
}

// blend 把 over 以其 alpha 叠加到 base 上。
func blend(base, over color.NRGBA) color.NRGBA {
	a := float64(over.A) / 255
	mix := func(b, o uint8) uint8 {
		return uint8(float64(b)*(1-a) + float64(o)*a)
	}
	return color.NRGBA{
		R: mix(base.R, over.R),
		G: mix(base.G, over.G),
		B: mix(base.B, over.B),
		A: 0xFF,
	}
}

// 程序主图标配色：深蓝底 + 白色同心环，取“隧道”意象。
var (
	colorAppBase = color.NRGBA{R: 0x12, G: 0x3A, B: 0x6B, A: 0xFF}
	colorAppRing = color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}
)

// AppIcon 返回程序主图标（用于任务栏、安装包与可执行文件资源）。
//
// 图标在构建期由 build/mkicon 生成成 PNG，再交给 go-winres 打进 exe，
// 因此仓库里不需要存放任何二进制资源。
func AppIcon(size int) *image.NRGBA {
	if size < 16 {
		size = 16
	}
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	center := float64(size-1) / 2
	outer := float64(size)/2 - float64(size)/32 - 0.5

	// 两道白环，环宽与间距按尺寸等比缩放，小尺寸下也不糊。
	ring1Out := outer * 0.74
	ring1In := outer * 0.56
	ring2Out := outer * 0.38
	ring2In := outer * 0.20

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			dx := float64(x) - center
			dy := float64(y) - center
			d := math.Sqrt(dx*dx + dy*dy)

			switch {
			case d > outer+1:
				// 圆外保持透明
			case d > outer:
				px := colorAppBase
				px.A = uint8(255 * (outer + 1 - d))
				img.SetNRGBA(x, y, px)
			case (d <= ring1Out && d >= ring1In) || (d <= ring2Out && d >= ring2In):
				img.SetNRGBA(x, y, colorAppRing)
			default:
				img.SetNRGBA(x, y, colorAppBase)
			}
		}
	}
	return img
}
