package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	path := "."
	// filepath walk 遍历制定目录下面
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			if path == "." || path == ".."{
				// 容错
				return nil
			}
			fmt.Println("is dir")
			fmt.Println(path)
			fmt.Println("===============")
			return nil
		}
		fmt.Println(path)
		fmt.Println("===============")
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}
}
