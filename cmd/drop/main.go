package main

import (
	"os"

	"github.com/thameem/drop/internal/cli"
)

func main() {
	os.Exit(cli.Execute(os.Args[1:]))
}
