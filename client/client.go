package client

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/TrustMetric/zoloz-open-api/utilities/encryption"
	"github.com/TrustMetric/zoloz-open-api/utilities/net_utils"
)

const DefaultAESLength = 32

type OpenAPIClient struct {
	HostURL            string
	ClientID           string
	MerchantPrivateKey string
	OpenAPIPublicKey   string
	Encrypted          bool
	IsLoadTest         bool
	AESLength          int
}

func NewOpenAPIClient(hostURL string, encrypted bool) *OpenAPIClient {
	return &OpenAPIClient{
		// Signed:    true,
		HostURL:   hostURL,
		Encrypted: encrypted,
		AESLength: DefaultAESLength,
	}
}

// func (c *OpenAPIClient) CallOpenAPI(apiName, request string) (result string, err error) {
/*
	1. Generate random AES key
	2. Encrypt the request using the randomly generated key
	3. Encrypt the AES key using RSA method with openAPIPublicKey
	4. Create a signature, the signature is "POST " + API URL + "\n" + Client ID + "." + formatted time + "." + encrypted request
		a. Generate PKCS8EncodedKeySpec from private key that got decoded from base64
		b. Create signature instance SHA256withRSA
		c. Sign the private key
*/

// var (
// 	encryptKey string
// 	key        []byte
// )

// if c.Encrypted {
// 	key, err = encryption.GenerateAESKey(c.AESLength)
// 	request = encryption.AESEncrypt()
// }

// 	return
// }

func (c *OpenAPIClient) CallOpenAPI(apiName, request string) (result string, err error) {
	requestTime := time.Now()
	// timeFormat := "2006-01-02T15:04:05Z0700"
	// formattedTime := requestTime.Format(timeFormat)
	formattedTime := requestTime.Format(time.RFC3339)
	formattedTime = formattedTime[:22] + formattedTime[23:]

	r, err := c.post(apiName, formattedTime, request)
	if err != nil {
		return "", err
	}
	result = string(r)

	log.Print(result)

	return result, nil
}

func (c *OpenAPIClient) post(apiName, requestTime, request string) (response []byte, err error) {

	var (
		aesKey          []byte
		encryptedAESKey string
	)

	if c.Encrypted {
		aesKey, err = encryption.GenerateAESKey(c.AESLength)
		if err != nil {
			return nil, err
		}

		log.Println("AES Key: " + string(aesKey))

		request, err = encryption.AESEncrypt(aesKey, request)
		if err != nil {
			return nil, err
		}

		log.Println("Encrypted Request: " + request + "\n")

		encryptedAESKey, err = encryption.RSAEncrypt(c.OpenAPIPublicKey, aesKey)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}

		log.Println("Encrypted AESKey: ", encryptedAESKey+"\n")
	}

	privateKey, err := encryption.DecodeBase64PrivateKey(c.MerchantPrivateKey)
	log.Println("Private key: " + privateKey.D.String() + "\n")
	if err != nil {
		panic(err)
	}

	unsignedContent := "POST " + apiName + "\n" + c.ClientID + "." + requestTime + "." + request
	log.Println("content to be signed:" + unsignedContent + "\n")

	signature := encryption.CreateSignature(unsignedContent, privateKey)
	log.Println("Signature is: " + signature + "\n")

	client := &http.Client{}
	req, _ := http.NewRequest(http.MethodPost, c.HostURL+apiName, bytes.NewBuffer([]byte(request)))

	if c.Encrypted {
		req.Header.Set(net_utils.HeaderContentType, net_utils.ContentTypePlainText)
		req.Header.Set(net_utils.HeaderEncrypt, "algorithm=RSA_AES, symmetricKey="+url.QueryEscape(encryptedAESKey))
	} else {
		req.Header.Set(net_utils.HeaderContentType, net_utils.ContentTypeJSON)
	}

	req.Header.Set(net_utils.HeaderClientId, c.ClientID)
	req.Header.Set(net_utils.HeaderRequestTime, requestTime)
	req.Header.Set(net_utils.HeaderSignature, "algorithm=RSA256, signature="+signature)

	if c.IsLoadTest {
		req.Header.Set(net_utils.HeaderLoadTestMode, "true")
	}
	res, err := client.Do(req)
	if err != nil {
		log.Println("Request failed!", err)
		return nil, err
	}

	log.Println("Response from Zoloz: ", res, "\n")

	respBody, err := io.ReadAll(res.Body)
	if err != nil {
		panic(err)
	}
	log.Println("Response body: ", respBody, "\n")

	if c.Encrypted {
		encryptHeader := res.Header.Get("Encrypt")
		log.Println("The headers: ")
		for i, v := range res.Header {
			log.Println("Key [", i, "]", "Value [", v, "]")
		}
		if encryptHeader == "" {
			return nil, errors.New("the Encrypt header is not found")
		}
		log.Println("Acquired Encrypt Header: ", encryptHeader)

		parts := strings.Split(encryptHeader, "symmetricKey=")
		if len(parts) < 2 {
			return nil, errors.New("symmetricKey not found in Encrypt header")
		}

		symmetricKey := strings.TrimSpace(parts[1]) // The encoded AES key
		log.Println("Acquired symmetricKey: ", symmetricKey)

		unescapedSymmetricKey, err := url.QueryUnescape(symmetricKey)
		if err != nil {
			return nil, err
		}
		log.Println("Unescaped Base64 Symmetric Key:", unescapedSymmetricKey)

		decryptedSymmetricKey, err := encryption.RSADecrypt(c.MerchantPrivateKey, unescapedSymmetricKey)
		if err != nil {
			log.Println("Failed to decrypt symmetric key!")
			return nil, err
		}

		decryptedResponse, _ := encryption.AESDecrypt(decryptedSymmetricKey, string(respBody))
		return []byte(decryptedResponse), nil
	}

	return respBody, nil

}

// func (c *OpenAPIClient) EncryptDecrypt() {
// 	merchatnPublicKey := "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgt+BOTUipQd9PzSG0lP8vAnxUCa5WxbFLwlp0lP8SrrsXv7qDXYXreLvzFGuOinjU1PxlJG641gAXe43vaHphXOp/d6SpwmCITXoNRAXwlUg5+YCk8gOwoAlojw+WMuM+WZjS0BNslB394iLhXk1BHl2ijABiSRM2EyS5JcrBW0o93CI64b9MZ8wBvhrlIgjR5BPe4J8vvhpUetR2Q/dF6fFnNGKkCdEqjOIphhREsEW0+W4hKRcToE6rGchSU4n6ictdA6JER6oTkspfpQxjz97hr20Z9pshvKtcNXQ1wFjnpPgpyn5lhSVWgnVZr+iBYiSyaYVXkskSY3B535EfwIDAQAB"
// 	text := "test"

// 	encrypted, _ := encryption.RSAEncrypt(merchatnPublicKey, []byte(text))
// 	decrypted, _ := encryption.RSADecrypt(c.MerchantPrivateKey, encrypted)
// 	fmt.Println(decrypted)
// }
