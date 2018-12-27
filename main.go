package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/pascaldekloe/jwt"
)

// ServiceAccount represents GCloud Service Account JSON
type ServiceAccount struct {
	PrivateKey        string `json:"private_key"`
	PrivateKeyID      string `json:"private_key_id"`
	ClientX509CertURL string `json:"client_x509_cert_url"`
	ClientEmail       string `json:"client_email"`
}

func main() {
	// Load Private Key
	serviceAccountBytes, err := ioutil.ReadFile("./service-account.json")
	if err != nil {
		panic(err)
	}

	var serviceAccount ServiceAccount
	json.Unmarshal(serviceAccountBytes, &serviceAccount)

	// Creating the JWT
	offset := time.Now()
	claims := jwt.Claims{
		Registered: jwt.Registered{
			Issuer:  serviceAccount.ClientEmail,
			Subject: serviceAccount.ClientEmail,
			// Audience designates parts of your API where this token can be used
			Audiences: []string{"https://yourapplication.com/designated/zone"},
			Expires:   jwt.NewNumericTime(offset.Add(time.Minute)),
			NotBefore: jwt.NewNumericTime(offset.Add(-time.Second)),
			Issued:    jwt.NewNumericTime(offset),
			ID:        "1234",
		},
		Set: map[string]interface{}{
			"is_cool": "true",
		},
	}

	//Load private key for the go lang library.
	keyBytes, _ := pem.Decode([]byte(serviceAccount.PrivateKey))

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBytes.Bytes)
	if err != nil {
		panic(err)
	}

	//Sign the Claims
	signedToken, err := claims.RSASign(jwt.RS256, privateKey.(*rsa.PrivateKey))

	if err != nil {
		panic(err)
	}

	// Fetch the public Key
	rs, err := http.Get(serviceAccount.ClientX509CertURL)

	if err != nil {
		panic(err)
	}

	defer rs.Body.Close()

	bodyBytes, err := ioutil.ReadAll(rs.Body)

	if err != nil {
		panic(err)
	}

	var publicKeys map[string]string
	json.Unmarshal(bodyBytes, &publicKeys)

	publicKeyString, ok := publicKeys[serviceAccount.PrivateKeyID]

	if !ok {
		log.Fatalf("No public key for %s", serviceAccount.PrivateKeyID)
	}

	publicCertBytes, _ := pem.Decode([]byte(publicKeyString))

	publicCert, err := x509.ParseCertificate(publicCertBytes.Bytes)

	if err != nil {
		panic(err)
	}

	validatedClaims, err := jwt.RSACheck(signedToken, publicCert.PublicKey.(*rsa.PublicKey))

	if err != nil {
		panic(err)
	}
	log.Printf("%v", validatedClaims)
}
