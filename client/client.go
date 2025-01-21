package client

type OpenAPIClient struct {
	HostURL            string
	ClientID           string
	MerchantPrivateKey string
	OpenAPIPublicKey   string
	Signed             bool
	Encrypted          bool
	IsLoadTest         bool
	AESLength          int
}

func NewOpenAPIClient() *OpenAPIClient {
	return &OpenAPIClient{
		Signed:    true,
		Encrypted: true,
	}
}
