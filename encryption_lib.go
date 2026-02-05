package configlib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

const (
	STORAGE_PREFIX_LENGTH = 3
	RANDOM_STRING_LENGTH  = 5
)

type KeyPair struct {
	AES  []byte
	HMAC []byte
}

func GenerateKeyPair(length int) (*KeyPair, error) {
	aesKey := make([]byte, length)
	hmacKey := make([]byte, length)

	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}
	if _, err := rand.Read(hmacKey); err != nil {
		return nil, err
	}

	return &KeyPair{
		AES:  aesKey,
		HMAC: hmacKey,
	}, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - (len(data) % blockSize)
	padding := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, padding...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("invalid padding size")
	}
	padLen := int(data[len(data)-1])
	return data[:len(data)-padLen], nil
}

func EncryptData(keyPair *KeyPair, data string) (string, error) {
	if data == "" {
		return "", nil
	}

	block, err := aes.NewCipher(keyPair.AES)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	plaintext := pkcs7Pad([]byte(data), aes.BlockSize)

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	mac := hmac.New(sha256.New, keyPair.HMAC)
	mac.Write(iv)
	mac.Write(ciphertext)
	tag := mac.Sum(nil)

	tagLen := fmt.Sprintf("%0*d", STORAGE_PREFIX_LENGTH, len(tag))
	ivLen := fmt.Sprintf("%0*d", STORAGE_PREFIX_LENGTH, len(iv))

	randStr := GenerateRandomString(RANDOM_STRING_LENGTH)

	full := randStr +
		strconv.Itoa(STORAGE_PREFIX_LENGTH) +
		tagLen + ivLen +
		string(tag) +
		string(iv) +
		string(ciphertext)

	return base64.StdEncoding.EncodeToString([]byte(full)), nil
}

func DecryptData(keyPair *KeyPair, data string) (string, error) {
	if data == "" {
		return "", nil
	}

	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	full := string(raw)
	full = full[RANDOM_STRING_LENGTH:]

	prefixLen, _ := strconv.Atoi(string(full[0]))
	full = full[1:]

	lengths := full[:prefixLen*2]
	tagLen, _ := strconv.Atoi(lengths[:prefixLen])
	ivLen, _ := strconv.Atoi(lengths[prefixLen : prefixLen*2])

	full = full[prefixLen*2:]

	tag := []byte(full[:tagLen])
	iv := []byte(full[tagLen : tagLen+ivLen])
	ciphertext := []byte(full[tagLen+ivLen:])

	mac := hmac.New(sha256.New, keyPair.HMAC)
	mac.Write(iv)
	mac.Write(ciphertext)
	expected := mac.Sum(nil)

	if !hmac.Equal(tag, expected) {
		return "", errors.New("HMAC verification failed")
	}

	block, err := aes.NewCipher(keyPair.AES)
	if err != nil {
		return "", err
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	unpadded, err := pkcs7Unpad(plaintext)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

func SaveKeyPair(keyPair *KeyPair, filepathStr string) error {
	filename := filepath.Clean(filepathStr)
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return err
	}

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	linfo := fmt.Sprintf("%0*d", STORAGE_PREFIX_LENGTH, len(keyPair.AES))

	f.Write([]byte{0x00})
	f.Write([]byte(strconv.Itoa(STORAGE_PREFIX_LENGTH)))
	f.Write([]byte(linfo))
	f.Write(keyPair.AES)
	f.Write(keyPair.HMAC)

	return nil
}

func LoadKeyPair(filepathStr string) (*KeyPair, error) {
	f, err := os.Open(filepathStr)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	f.Read(make([]byte, 1))

	prefix := make([]byte, 1)
	f.Read(prefix)
	prefixLen, _ := strconv.Atoi(string(prefix))

	lenBuf := make([]byte, prefixLen)
	f.Read(lenBuf)
	keyLen, _ := strconv.Atoi(string(lenBuf))

	aesKey := make([]byte, keyLen)
	io.ReadFull(f, aesKey)

	hmacKey, _ := io.ReadAll(f)

	return &KeyPair{
		AES:  aesKey,
		HMAC: hmacKey,
	}, nil
}

func GenerateRandomString(size int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, size)
	rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}
