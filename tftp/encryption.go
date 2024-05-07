package tftp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
)


// ========= Struct for Key Generation and Storage =========

type EncryptionManager struct {
	privateKey *rsa.PrivateKey
	sharedKey  []byte
}

func NewEncryptionManager() (*EncryptionManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	sharedKey := make([]byte, 32)
	_, err = rand.Reader.Read(sharedKey)
	if err != nil {
		readKeyErr := &throwErrors{
			err, "Reading Shared Key",
		}
		return nil, readKeyErr
	}

	return &EncryptionManager{
		privateKey: privateKey,
		sharedKey:  sharedKey,
	}, nil
}

// ========= RSA Encryption / Decryption =========

func rsaEncrypt(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, message)
}

func rsaDecrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)
}



// ========= AES Encryption / Decryption =========

func encryptPacket(packet []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		encryptCiphErr := &throwErrors{
			err, "Encrypt Cipher Key",
		}
		return nil, encryptCiphErr
	}
	ciphertext := make([]byte, aes.BlockSize+len(packet))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		readCiphErr := &throwErrors{
			err, "Reading Cipher",
		}
		return nil, readCiphErr
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], packet)
	return ciphertext, nil
}

func decryptPacket(packet []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		decryptCiphErr := &throwErrors{
			err, "Decrypt Cipher Key",
		}
		return nil, decryptCiphErr
	}
	if len(packet) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	iv := packet[:aes.BlockSize]
	ciphertext := packet[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	plaintext := make([]byte, len(ciphertext))
	stream.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}
