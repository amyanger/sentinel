package main

import (
	"fmt"
	"os"
)

const version = "0.1.0"

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "version" {
		fmt.Println("sentinel-collector", version)
		return
	}
	fmt.Fprintln(os.Stderr, "usage: collector [version|serve|admin]")
	os.Exit(2)
}
