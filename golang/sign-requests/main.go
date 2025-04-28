package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/yaronf/httpsign"
)

const VerifyUrl = "https://api.griffin.com/v0/security/message-signature/verify"

// loadPrivateKey reads an Ed25519 private key from a PEM file
// Follow our guides to generate a public/private key pair
// https://docs.griffin.com/docs/guides/how-to-create-message-signatures#create-a-public-and-private-key
func loadPrivateKey(filepath string) (ed25519.PrivateKey, error) {
	pemData, err := os.ReadFile(filepath)
	if err != nil {
		return nil, fmt.Errorf("error reading PEM file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Parse the private key
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 private key")
	}

	return ed25519Key, nil
}

// generateContentDigest creates a SHA-512 digest of the request body
func generateContentDigest(body []byte) string {
	hash := sha512.Sum512(body)
	encoded := base64.StdEncoding.EncodeToString(hash[:])
	return fmt.Sprintf("sha-512=:%s:", encoded)
}

func main() {
	// https://docs.griffin.com/docs/introduction/get-started-with-the-api#creating-an-api-key
	apiKey := os.Getenv("GRIFFIN_API_KEY")
	if apiKey == "" {
		fmt.Println("Please set the GRIFFIN_API_KEY environment variable")
		return
	}

	// You can retrieve the keyid through
	// https://docs.griffin.com/docs/guides/how-to-create-message-signatures#view-your-public-keys
	keyId := os.Getenv("GRIFFIN_KEY_ID")
	if keyId == "" {
		fmt.Println("Please set the GRIFFIN_KEY_ID environment variable")
		return
	}

	privateKeyPath := "private_key.pem"
	if path := os.Getenv("GRIFFIN_PRIVATE_KEY_PATH"); path != "" {
		privateKeyPath = path
	}

	// Load the private key
	ed25519Key, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		fmt.Println("Error loading private key:", err)
		return
	}

	fmt.Printf("Successfully loaded Ed25519 private key. Public key: %x\n", ed25519Key.Public())

	// A new one should be generated at every request
	nonce := uuid.New().String()

	// Setting an expires to 5 min from now
	expires := time.Now().Add(5 * time.Minute).UTC().Unix()

	signConfig := httpsign.NewSignConfig().
		SignAlg(true).
		SetKeyID(keyId).
		SetNonce(nonce).
		SetTag("sig1").
		SignCreated(true).
		SetExpires(expires)

	signerFields := httpsign.NewFields()
	signerFields.AddHeaders("@method", "@authority", "@path", "content-type", "content-length", "date", "content-digest")

	signer, err := httpsign.NewEd25519Signer(ed25519Key, signConfig, *signerFields)
	if err != nil {
		fmt.Println("httpsign.NewEd25519Signer failed", err)
		return
	}

	req, err := http.NewRequest("GET", VerifyUrl, nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Add("Authorization", "GriffinAPIKey "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	// GET request, no body
	req.Header.Set("Content-Length", "") 

	// The date format is arbitary. Not verified.
	timeNow := time.Now().Format(time.RFC1123) 
	req.Header.Set("Date", timeNow)

	// GET request, no body hence no digest
	digest := generateContentDigest(nil) 
	req.Header.Set("Content-Digest", digest)

	transport := &http.Transport{
		DisableCompression: true,
	}
	httpClient := &http.Client{Transport: transport}

	client := httpsign.NewClient(*httpClient, httpsign.NewClientConfig().SetSignatureName("sig1").SetSigner(signer))
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	// Print status code and response
	fmt.Println("Status:", resp.Status)
	fmt.Println("Response body:", string(body))

	// Print headers for debugging
	fmt.Println("\nRequest headers sent:")
	for name, values := range req.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", name, value)
		}
	}

}
