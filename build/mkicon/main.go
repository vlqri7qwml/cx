// Command mkicon 生成构建期需要的图标文件。
//
// 图标由代码画出来，而不是作为二进制文件提交进仓库：
// 这样它与托盘图标共用同一套配色，也不会出现“图标改了但没人知道”的问题。
//
//	go run ./build/mkicon -out build/icon.png -size 256
//	go run ./build/mkicon -ico build/icon.ico
package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"

	"github.com/vlqri7qwml/cx/internal/ui"
)

// icoSizes 是 .ico 里包含的尺寸，覆盖任务栏、资源管理器与安装程序。
var icoSizes = []int{16, 32, 48, 64, 128, 256}

func main() {
	out := flag.String("out", "", "输出 PNG 路径")
	size := flag.Int("size", 256, "PNG 图标边长（像素）")
	ico := flag.String("ico", "", "输出多尺寸 ICO 路径")
	flag.Parse()

	if *out == "" && *ico == "" {
		fmt.Fprintln(os.Stderr, "请用 -out 指定 PNG 输出，或用 -ico 指定 ICO 输出")
		os.Exit(2)
	}

	if *out != "" {
		if err := writeFile(*out, func(f *os.File) error {
			return png.Encode(f, ui.AppIcon(*size))
		}); err != nil {
			fail(err)
		}
		fmt.Printf("已生成 %s (%dx%d)\n", *out, *size, *size)
	}

	if *ico != "" {
		images := make([]image.Image, 0, len(icoSizes))
		for _, s := range icoSizes {
			images = append(images, ui.AppIcon(s))
		}
		if err := writeFile(*ico, func(f *os.File) error {
			return writeICO(f, images)
		}); err != nil {
			fail(err)
		}
		fmt.Printf("已生成 %s (%v)\n", *ico, icoSizes)
	}
}

func writeFile(path string, fn func(*os.File) error) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := fn(f); err != nil {
		return err
	}
	return f.Close()
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "生成图标失败: %v\n", err)
	os.Exit(1)
}
