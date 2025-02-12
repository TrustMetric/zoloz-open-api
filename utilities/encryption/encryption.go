package encryption

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
)

func GenerateAESKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func AESEncrypt(key []byte, content string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// // iv := make([]byte, aes.BlockSize)
	// // if _, err := io.ReadFull(rand.Reader, iv); err != nil {
	// // 	return "", err
	// // }

	// ciphertext := make([]byte, len(content))
	// stream := cipher.NewCFBEncrypter(block, iv)
	// stream.XORKeyStream(ciphertext, []byte(content))

	// result := append(iv, ciphertext...)

	paddedContent := PKCS5Padding([]byte(content), block.BlockSize())

	ciphertext := make([]byte, len(paddedContent))
	for i := 0; i < len(paddedContent); i += block.BlockSize() {
		block.Encrypt(ciphertext[i:i+block.BlockSize()], paddedContent[i:i+block.BlockSize()])
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func PKCS5Padding(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func RSAEncrypt(publicKeyPEM string, content []byte) (string, error) {

	wrappedPEM := NormalizePEM(publicKeyPEM, "PUBLIC")

	block, _ := pem.Decode([]byte(wrappedPEM))

	if block == nil || block.Type != "PUBLIC KEY" {
		return "", errors.New("failed to decode PEM block containing public key")
	}

	// Parse the public key
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	log.Println("PKIXPublicKey: ", pub, "\n")

	// Type assert to RSA public key
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return "", err
	}

	log.Println("RSA Public Key: ", rsaPub, "\n")

	// Encrypt the plaintext
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, content)
	if err != nil {
		return "", err
	}

	log.Println("Encrypted text", ciphertext, "\n")

	// Encode the ciphertext as Base64
	encoded := base64.StdEncoding.EncodeToString(ciphertext)

	log.Println("Encoded Content: ", encoded, "\n")

	return encoded, nil
}

func RSADecrypt(privateKeyPEM, content string) (string, error) {
	// decoded, err := base64.StdEncoding.DecodeString(content)
	// if err != nil {
	// 	log.Println(err)
	// 	return "", err
	// }
	// log.Println("Content decoded\n")

	// wrappedPEM := NormalizePEM(privateKeyPEM, "PRIVATE")
	// log.Println("PEM Normalized\n")

	// block, _ := pem.Decode([]byte(wrappedPEM))
	// if block == nil || block.Type != "PRIVATE KEY" {
	// 	log.Println("Block Type: ", block.Type)
	// 	return "", errors.New("failed to decode PEM block containing private key")
	// }
	// log.Println("Acquired Block")

	// // Parse the private key
	// priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	// if err != nil {
	// 	return "", err
	// }

	// log.Println("PKCS8PrivateKey: ", priv, "\n")

	// // Type assert to RSA private key
	// rsaPrivateKey, ok := priv.(*rsa.PrivateKey)
	// if !ok {
	// 	return "", errors.New("not an RSA private key")
	// }
	// log.Println("RSA Private Key: ", rsaPrivateKey, "\n")

	// decryptedResult, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, decoded)
	// if err != nil {
	// 	log.Println(err)
	// 	return "", err
	// }
	// log.Println("Content decrypted: ", decryptedResult, "\n")

	// return string(decryptedResult), nil
	// Decode Base64-encoded ciphertext

	decodedCiphertext, err := base64.StdEncoding.DecodeString(content)
	if err != nil {
		log.Println("Failed to decode from base64: ", err)
		return "", err
	}

	log.Println("Decoded cipher text: ", string(decodedCiphertext))

	// Normalize and parse the private key
	privateKeyPEM = NormalizePEM(privateKeyPEM, "PRIVATE")

	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil || block.Type != "PRIVATE KEY" {
		log.Println("Failed to decode PEM: ")
		return "", errors.New("failed to decode PEM block containing private key")
	}
	log.Println("Decoded PEM: ", block)

	// Parse private key
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		priv, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			log.Println("Failed to parse private key: ", err)
			return "", err
		}
	}

	log.Println("Parsed private key: ", priv)

	// Type assert to RSA private key
	rsaPrivateKey, ok := priv.(*rsa.PrivateKey)
	if !ok {
		log.Println("Failed to assert key: ", err)
		return "", errors.New("not an RSA private key")
	}

	log.Println("Parsed private key: ", priv)

	// Decrypt the content
	decryptedData, err := rsa.DecryptPKCS1v15(rand.Reader, rsaPrivateKey, decodedCiphertext)
	if err != nil {
		log.Println("Failed to decrypt key: ", err)
		return "", err
	}

	return string(decryptedData), nil
}

func NormalizePEM(keyPEM, keyType string) string {

	keyPEM = strings.TrimSpace(keyPEM)
	keyPEM = strings.ReplaceAll(keyPEM, "-----BEGIN PUBLIC KEY-----", "")
	keyPEM = strings.ReplaceAll(keyPEM, "-----BEGIN PRIVATE KEY-----", "")
	keyPEM = strings.ReplaceAll(keyPEM, "-----BEGIN RSA PRIVATE KEY-----", "")
	keyPEM = strings.ReplaceAll(keyPEM, "-----END PUBLIC KEY-----", "")
	keyPEM = strings.ReplaceAll(keyPEM, "-----END PRIVATE KEY-----", "")
	keyPEM = strings.ReplaceAll(keyPEM, "-----END RSA PRIVATE KEY-----", "")
	keyPEM = strings.TrimSpace(keyPEM)

	if keyType == "PUBLIC" {
		return "-----BEGIN PUBLIC KEY-----\n" + keyPEM + "\n-----END PUBLIC KEY-----"
	}

	return "-----BEGIN PRIVATE KEY-----\n" + keyPEM + "\n-----END PRIVATE KEY-----"
}

func DecodeBase64PrivateKey(key string) (*rsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(b)
}

func DecodeBase64ToPEM(base64Key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", err
	}

	// Wrap the decoded key in PEM format
	pemKey := fmt.Sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", base64.StdEncoding.EncodeToString(decoded))
	return pemKey, nil

}

func ParsePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	pri, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	p, ok := pri.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid private key")
	}
	return p, nil
}

func CreateSignature(unsignedContent string, privateKey *rsa.PrivateKey) string {
	message := []byte(unsignedContent)
	hashed := sha256.Sum256(message)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, hashed[:])
	if err != nil {
		panic(err)
	}
	signature := base64.StdEncoding.EncodeToString(sigBytes)
	signature = url.QueryEscape(signature)
	return signature
}
