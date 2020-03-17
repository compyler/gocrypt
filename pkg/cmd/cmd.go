package cmd

import (
	"gocrypt/pkg/cmd/decrypt"
	"gocrypt/pkg/cmd/encypt"

	"github.com/spf13/cobra"
)

func NewCryptCommand() *cobra.Command {
	cmds := &cobra.Command{
		Use: "crypt",
	}

	encryptCmd := encypt.NewCmdEncrypt()
	decryptCmd := decrypt.NewCmdDecrypt()

	cmds.AddCommand(encryptCmd)
	cmds.AddCommand(decryptCmd)

	cmds.PersistentFlags().StringP("input", "i", "", "name of input file")
	cmds.PersistentFlags().StringP("output", "o", "", "name of output file to save data")

	return cmds
}
