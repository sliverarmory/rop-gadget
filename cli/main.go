package main

import (
	"fmt"
	"os"

	ropgadget "github.com/sliverarmory/rop-gadget"
)

func main() {
	if err := ropgadget.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
