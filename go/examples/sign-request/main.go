package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	tlsigning "github.com/Truelayer/truelayer-signing/go"
	"github.com/google/uuid"
)

// the base url to use
const (
	TlBaseURL = "https://api.truelayer-sandbox.com"
)

func main() {
	// Read required env vars
	kid, found := os.LookupEnv("KID")
	if !found {
		fmt.Println("Missing env var KID")
		os.Exit(1)
	}
	accessToken, found := os.LookupEnv("ACCESS_TOKEN")
	if !found {
		fmt.Println("Missing env var ACCESS_TOKEN")
		os.Exit(1)
	}
	privateKey, found := os.LookupEnv("PRIVATE_KEY")
	if !found {
		fmt.Println("Missing env var PRIVATE_KEY")
		os.Exit(1)
	}

	// Set Body here
	body := `{"amount_in_minor":1,"currency":"GBP","payment_method":{"type":"bank_transfer","provider_selection":{"type":"preselected","provider_id":"mock-payments-gb-redirect","scheme_id":"faster_payments_service"},"beneficiary":{"type":"merchant_account","account_holder_name":"Merchant Account name","merchant_account_id":"cc12f006-f94f-41bf-b093-34a005fa2e1e"}},"user":{"id":"57e9ae89-01fd-4779-8775-5b7de9a85a64","name":"Test","email":"test@gmail.com","phone":"+3634455433456"}}`

	idempotencyKey := uuid.New().String()
	contentType := "application/json"

	// Generate tl-signature
	tlSignature, err := tlsigning.SignWithPem(kid, []byte(privateKey)).
		Method("POST"). // as we're sending a POST request
		Path("/payments").
		Header("Idempotency-Key", []byte(idempotencyKey)).
		Header("Content-Type", []byte(contentType)).
		Body([]byte(body)). // body of our request
		Sign()

	if err != nil {
		fmt.Printf("Failed signing: %s\n", err.Error())
		os.Exit(1)
	}

	fmt.Println("Sending...")

	// Request body & any signed headers *must* exactly match what was used to generate the signature.
	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/payments", TlBaseURL), strings.NewReader(body))
	if err != nil {
		fmt.Printf("Failed request creation: %s\n", err.Error())
		os.Exit(1)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	req.Header.Add("Idempotency-Key", idempotencyKey)
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Tl-Signature", tlSignature)
	resp, err := client.Do(req)

	statusCode := -1
	var responseBody string
	if err == nil {
		statusCode = resp.StatusCode
		if statusCode == 204 {
			responseBody = "✓"
		} else {
			defer resp.Body.Close()
			responseBodyBytes, err := io.ReadAll(resp.Body)
			if err == nil {
				responseBody = string(responseBodyBytes)
			} else {
				responseBody = fmt.Sprintf("Failed reading response body: %s", err.Error())
			}
		}
	} else {
		responseBody = fmt.Sprintf("Test signature request failed: %s", err.Error())
	}

	// 204 means success
	// 401 means either the access token is invalid, or the signature is invalid.
	fmt.Printf("%d %s\n", statusCode, responseBody)
}
