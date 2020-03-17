package decrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

func NewCmdDecrypt() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "decrypt ([-in FILENAME] [-out FILENAME] [-key FILENAME])",
		Aliases: []string{"dec"},
		Run: func(cmd *cobra.Command, args []string) {
			decrypt(cmd, args)
		},
	}

	return cmd
}

func decrypt(cmd *cobra.Command, args []string) {
	inFile := cmd.Flag("input").Value.String()
	outFile := cmd.Flag("output").Value.String()

	pass := getPassword()
	key := deriveKey(pass)

	b, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln("creating new cipher has failed")
	}
	iv := make([]byte, aes.BlockSize)
	bm := cipher.NewCBCDecrypter(b, iv)

	in, err := os.Open(inFile) // For read access.
	if err != nil {
		log.Fatal(err)
	}
	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644) // For write access.
	if err != nil {
		log.Fatal(err)
	}

	bb := make([]byte, 8)
	_, err = in.Read(bb)
	if err != nil {
		log.Fatalln("cannot read file: ", err)
	}
	size := int(binary.LittleEndian.Uint64(bb))

	src := make([]byte, aes.BlockSize*1024)
	dst := make([]byte, aes.BlockSize*1024)
	for {
		n, err := in.Read(src)
		if err == io.EOF && n == 0 {
			break
		}
		if err != nil {
			log.Fatal("cannot read file", err)
		}

		bm.CryptBlocks(dst, src)

		if size < n {
			_, err = out.Write(dst[:size])
			if err != nil {
				log.Fatal("cannot write file", err)
			}
			break
		}
		_, err = out.Write(dst[:n])
		if err != nil {
			log.Fatal("cannot write file", err)
		}
		size = size - n
	}
}

func getPassword() []byte {
	fmt.Print("Gimme da password: ")
	pass, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		log.Fatal("Error reading password: ", err)
	}
	return pass
}

func deriveKey(pass []byte) []byte {
	salt := make([]byte, 32)
	key := argon2.IDKey(pass, salt, 1, 32*1024, 2, 32)
	return key
}
