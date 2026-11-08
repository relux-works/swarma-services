package main

import (
	"github.com/relux-works/swarma-services/prepublish-gate/internal/gate"
	"github.com/relux-works/swarma-services/prepublish-gate/internal/tails"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "tails" {
		os.Exit(tails.Run(os.Args[2:], os.Stdout))
	}
	os.Exit(gate.Run(os.Args[1:], os.Stdout))
}
