package main

import (
	"gocrypt/pkg/cmd"
	"os"
)

func main() {
	command := cmd.NewCryptCommand()

	if err := command.Execute(); err != nil {
		os.Exit(1)
	}
}
