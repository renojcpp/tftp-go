package tftp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
)

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
		return nil, err
	}

	return &EncryptionManager{
		privateKey: privateKey,
		sharedKey:  sharedKey,
	}, nil
}

func rsaEncrypt(publicKey *rsa.PublicKey, message []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, message) 
}

func rsaDecrypt(privateKey *rsa.PrivateKey, ciphertext []byte) ([]byte, error) {
	return rsa.DecryptPKCS1v15(nil, privateKey, ciphertext)  
}

func (s *ServerConnection) StartKeyExchange() error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&s.encryption.privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err) 
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	_, err = s.conn.Write(publicKeyPEM) 
	return err
}

func (c *Client) CompleteKeyExchange(publicKeyPEM []byte) error {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return fmt.Errorf("invalid public key PEM")
	}

	serverPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	symmetricKey := make([]byte, 32) 
	_, err = rand.Reader.Read(symmetricKey)
	if err != nil {
		return err
	}

	encryptedSymmetricKey, err := rsaEncrypt(serverPublicKey.(*rsa.PublicKey), symmetricKey)
	if err != nil {
		return err
	}

	_, err = c.conn.Write(encryptedSymmetricKey)
	c.encryption.sharedKey = symmetricKey
	return err
}

func (s *ServerConnection) CompleteKeyExchange() error {
	encryptedSymmetricKey := make([]byte, 256) 
	n, err := s.readWriter.Read(encryptedSymmetricKey)
	if err != nil {
		return err
	}

	symmetricKey, err := rsaDecrypt(s.encryption.privateKey, encryptedSymmetricKey[:n])
	if err != nil {
		return err
	}

	s.encryption.sharedKey = symmetricKey
	return nil
}

func encryptPacket(packet []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, aes.BlockSize + len(packet))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], packet)
	return ciphertext, nil
}

func decryptPacket(packet []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
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

func (c *Client) WriteEncryptedPacket(packet []byte) error {
	encryptedPacket, err := encryptPacket(packet, c.encryption.sharedKey)
	if err != nil {
		return err
	}
	_, err = c.conn.Write(encryptedPacket)
	return err
}

func (c *Client) ReadDecryptedPacket() ([]byte, error) {
	packet := make([]byte, 512)
	n, err := c.reader.Read(packet)
	if err != nil {
		return nil, err
	}
	return decryptPacket(packet[:n], c.encryption.sharedKey)
}

func (s *ServerConnection) WriteEncryptedResponse(packet []byte) error {
	encryptedPacket, err := encryptPacket(packet, s.encryption.sharedKey)
	if err != nil{
		 return err
	}
	_, err = s.conn.Write(encryptedPacket)
	return err
}

func (s *ServerConnection) ReadEncryptedRequest() ([]byte, error) {
	packet := make([]byte, 512)
	n, err := s.readWriter.Read(packet)
	if err != nil{
		 return nil, err
	}
	return decryptPacket(packet[:n], s.encryption.sharedKey)
}

