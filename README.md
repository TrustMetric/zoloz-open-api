# ZOLOZ OpenAPI SDK

## Description
This repository provides an SDK to help customers integrate the ZOLOZ SaaS API with ease.

## Features
- Supports both unencrypted & encrypted request modes
- Implements request signatures to ensure data integrity and prevent tampering

## Installation
```sh
# Navigate to the project directory
cd yourproject

# Install the SDK
go get github.com/TrustMetric/zoloz-open-api
```

## Usage
```go
// Import the library
import (
    "github.com/TrustMetric/zoloz-open-api/client"
)

// Initialize the OpenAPI client
client := client.NewOpenAPIClient("[url]", true)

// [url] should be replaced with the host environment, e.g., https://sg-production-api.zoloz.com.
// Contact Zoloz technical support to confirm the correct host.

// The second parameter determines encryption mode:
// - true: Requests and responses will be encrypted.
// - false: Requests and responses will not be encrypted.

// Set client configurations
client.ClientID = "218...495"
client.MerchantPrivateKey = "MIIEv...bJc="
client.OpenAPIPublicKey = "MIIBI...AQAB"

// The Client ID can be found in the Zoloz Portal.
// Ensure that your Merchant (Public) Key is set in the Zoloz Portal under Integration > API Key.

// Call the API
result, err := client.CallOpenAPI(apiPath, requestBody)

// The API Path and the Request Body format can be found in the Zoloz Documentation:
// https://docs.zoloz.com/zoloz/saas/apireference/apilist
```

## Usage Example
```go
package main

import (
    "fmt"
    "github.com/TrustMetric/zoloz-open-api/client"
)

const merchantPrivateKey string = "MIIEv...bJc="
const zolozPublicKey string = "MIIBI...DAQAB"
const clientID string = "218...495"

const apiPath string = "/api/v1/zoloz/authentication/test"

func main() {
    requestBody := "{\"title\":\"hello\",\"description\":\"just for demonstration.\"}"
    client := client.NewOpenAPIClient("https://sg-sandbox-api.zoloz.com", true)
    client.ClientID = clientID
    client.MerchantPrivateKey = merchantPrivateKey
    client.OpenAPIPublicKey = zolozPublicKey

    result, err := client.CallOpenAPI(apiPath, requestBody)
    if err != nil {
        fmt.Println("Error calling API:", err)
        return
    }

    fmt.Println("The result is below:")
    fmt.Println(result)
}
```