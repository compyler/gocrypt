package encypt

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

func NewCmdEncrypt() *cobra.Command {

	cmd := &cobra.Command{
		Use:     "encrypt ([-in FILENAME] [-out FILENAME] [-key FILENAME])",
		Aliases: []string{"enc"},
		Run: func(cmd *cobra.Command, args []string) {
			encrypt(cmd, args)
		},
	}

	return cmd
}

func encrypt(cmd *cobra.Command, args []string) {
	inFile := cmd.Flag("input").Value.String()
	outFile := cmd.Flag("output").Value.String()

	pass := getPassword()
	key := deriveKey(pass)

	b, err := aes.NewCipher(key)
	if err != nil {
		log.Fatalln("creating new cipher has failed")
	}
	iv := make([]byte, aes.BlockSize)
	bm := cipher.NewCBCEncrypter(b, iv)

	in, err := os.Open(inFile) // For read access.
	if err != nil {
		log.Fatal(err)
	}
	out, err := os.OpenFile(outFile, os.O_CREATE|os.O_WRONLY, 0644) // For write access.
	if err != nil {
		log.Fatal(err)
	}
	inStat, _ := in.Stat()
	size := inStat.Size()
	bb := make([]byte, 8)
	binary.LittleEndian.PutUint64(bb, uint64(size))
	_, err = out.Write(bb)
	if err != nil {
		log.Fatal("cannot write to file: ", err)
	}

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
		if n < aes.BlockSize {
			for i := n; i < aes.BlockSize*1024; i++ {
				src[i] = 0
			}
		}

		bm.CryptBlocks(dst, src)
		_, err = out.Write(dst)
		if err != nil {
			log.Fatal("cannot write file", err)
		}
	}

}

func getPassword() []byte {
	fmt.Print("Gimme da password: ")
	pass, err := terminal.ReadPassword(0)
	fmt.Println()
	if err != nil {
		log.Fatal("Error reading pasword: ", err)
	}
	return pass
}

func deriveKey(pass []byte) []byte {
	salt := make([]byte, 32)
	key := argon2.IDKey(pass, salt, 1, 32*1024, 2, 32)
	return key
}
