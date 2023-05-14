package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

const EncryptedExtension = "cipher"
const Salt = "randomsalt"
const KeySize = 32

func main() {
	var password string
	fmt.Printf("Password: ")
	fmt.Scanln(&password)

	password = strings.TrimSpace(password)
	if password == "" {
		fmt.Println("Password cannot be empty")
		os.Exit(1)
	}

	dir, err := os.ReadDir(".")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for _, f := range dir {
		parts := strings.Split(f.Name(), ".")
		ext := ""
		if len(parts) >= 2 {
			ext = parts[1]
		}

		if !f.IsDir() && (ext == "txt" || ext == EncryptedExtension) {
			filename := f.Name()
			if ext == "txt" {
				err := encryptFile(filename, password)
				if err != nil {
					fmt.Printf("Encryption failed for %s: %v\n", filename, err)
				} else {
					fmt.Printf("Encrypted %s\n", filename)
				}
			} else if ext == EncryptedExtension {
				err := decryptFile(filename, password)
				if err != nil {
					fmt.Printf("Decryption failed for %s: %v\n", filename, err)
				} else {
					fmt.Printf("Decrypted %s\n", filename)
				}
			}
		}
	}

}

func encryptFile(filename string, password string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	encrypted, err := encrypt(string(b), password)
	if err != nil {
		return err
	}

	newFilename := strings.TrimSuffix(filename, ".txt") + "." + EncryptedExtension
	err = os.WriteFile(newFilename, encrypted, 0644)
	if err != nil {
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	err = os.Remove(filename)
	if err != nil {
		return err
	}

	return nil
}

func decryptFile(filename string, password string) error {
	f, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	decrypted, err := decrypt(string(b), password)
	if err != nil {
		return err
	}
	decrypted = []byte(strings.TrimRight(string(decrypted), "\x00-\x1F\x7F"))

	valid, err := isDataValid(decrypted)
	if err != nil {
		return err
	}

	if !valid {
		return fmt.Errorf("invalid decrypted data, check the password")
	}

	newFilename := strings.TrimSuffix(filename, "."+EncryptedExtension) + ".txt"
	err = os.WriteFile(newFilename, removeNonPrintables(decrypted), 0644)
	if err != nil {
		return err
	}

	err = f.Close()
	if err != nil {
		return err
	}

	err = os.Remove(filename)
	if err != nil {
		return err
	}

	return nil
}

func encrypt(text string, password string) ([]byte, error) {
	key := deriveKey(password, []byte(Salt), KeySize)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedText := pkcs7Pad([]byte(text), aes.BlockSize)
	cipherText := make([]byte, len(paddedText))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, paddedText)
	cipherText = append(iv, cipherText...)
	encodedData := base64.StdEncoding.EncodeToString(cipherText)
	return []byte(encodedData), nil
}

func decrypt(cipherText string, password string) ([]byte, error) {
	decodedData, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}

	key := deriveKey(password, []byte(Salt), KeySize)
	iv := decodedData[:aes.BlockSize]
	decodedData = decodedData[aes.BlockSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plainText := make([]byte, len(cipherText))
	mode.CryptBlocks(plainText, decodedData)

	plainText = pkcs7Unpad(plainText)
	return plainText, nil
}

func deriveKey(password string, salt []byte, keySize int) []byte {
	data := append([]byte(password), salt...)
	hash := sha256.New()
	for i := 0; i < 1000; i++ {
		hash.Write(data)
		data = hash.Sum(nil)
		hash.Reset()
	}
	key := make([]byte, keySize)
	copy(key, data)
	return key
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) []byte {
	padding := int(data[len(data)-1])
	return data[:len(data)-padding]
}

func isDataValid(data []byte) (bool, error) {
	str := string(data)
	return utf8.ValidString(str), nil
}

func removeNonPrintables(data []byte) []byte {
	var result []byte
	for _, b := range data {
		if b >= 32 && b <= 126 {
			result = append(result, b)
		}
	}
	return result
}
