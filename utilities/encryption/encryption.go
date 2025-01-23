package encryption

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"net/url"
)

func GenerateAESKey(length int) ([]byte, error) {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func DecodeBase64PrivateKey(key string) (*rsa.PrivateKey, error) {
	b, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKey(b)
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
